// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `caliptra-rom-patch` — Caliptra MCU ROM patch packer (RFC-0001).
//!
//! Two modes:
//! - single patch: `--replacement … --target … --signing-key … --out block.bin`
//!   packs + signs one block (optionally `--emit-fuse-cfg`).
//! - patch set: `--manifest patches.hjson --out add-cfg.hjson` packs every patch
//!   in the manifest, validates the set, and emits one combined `--add-cfg`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;

use caliptra_rom_patch::elf::rom_executable_ranges;
use caliptra_rom_patch::manifest::{self, Placement};
use caliptra_rom_patch::signer::{PatchSigner, SeedSigner};
use caliptra_rom_patch::{build_patch_block, fuse_cfg, PatchRequest, RomBounds};

/// Pack and sign Caliptra MCU ROM patch block(s) (PMP trap-and-patch, RFC-0001).
#[derive(Debug, Parser)]
#[command(
    name = "caliptra-rom-patch",
    about = "Pack and Ed25519-sign Caliptra MCU ROM patch block(s) (PMP trap-and-patch, RFC-0001)",
    disable_version_flag = true
)]
struct Args {
    /// Patch-set manifest (hjson): packs every patch and emits one combined
    /// --add-cfg to --out. Mutually exclusive with the single-patch flags.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Pre-built, position-independent, relocation-free replacement ELF.
    /// Its entry point (`patch_fn`) must be at the image base.
    #[arg(
        long,
        required_unless_present = "manifest",
        conflicts_with = "manifest"
    )]
    replacement: Option<PathBuf>,

    /// Absolute target ROM address (4-byte aligned). Accepts 0x-hex or decimal.
    #[arg(long, value_parser = parse_u32, required_unless_present = "manifest", conflicts_with = "manifest")]
    target: Option<u32>,

    /// Resume offset in 4-byte words from the target (non-zero).
    #[arg(long, conflicts_with_all = ["resume_addr", "manifest"])]
    resume_offset: Option<u16>,

    /// Absolute resume address (4-byte aligned, > target); offset = (addr-target)/4.
    #[arg(long, value_parser = parse_u32, conflicts_with = "manifest")]
    resume_addr: Option<u32>,

    /// Patch format / ABI version (header bits 23:16).
    #[arg(long, default_value_t = 1, conflicts_with = "manifest")]
    version: u8,

    /// Set the CRITICAL flag (failures fail closed).
    #[arg(long, conflicts_with = "manifest")]
    critical: bool,

    /// Raw 32-byte Ed25519 seed file used to sign the patch payload.
    #[arg(
        long,
        required_unless_present = "manifest",
        conflicts_with = "manifest"
    )]
    signing_key: Option<PathBuf>,

    /// Total OTP slot size in bytes (code is bounded to slot_size - 0x4C).
    #[arg(long, conflicts_with = "manifest")]
    slot_size: Option<usize>,

    /// ROM ELF: validates target & resume fall in an executable ROM section.
    #[arg(long, conflicts_with_all = ["rom_base", "rom_size", "manifest"])]
    rom_elf: Option<PathBuf>,

    /// ROM base address for the target in-range check.
    #[arg(long, value_parser = parse_u32, requires = "rom_size", conflicts_with = "manifest")]
    rom_base: Option<u32>,

    /// ROM size in bytes for the target in-range check.
    #[arg(long, value_parser = parse_u32, requires = "rom_base", conflicts_with = "manifest")]
    rom_size: Option<u32>,

    /// Output: signed block (single mode) or combined --add-cfg hjson (manifest).
    #[arg(long)]
    out: PathBuf,

    /// Optional output path for the Ed25519 public key (32 bytes), for slot 0.
    #[arg(long, conflicts_with = "manifest")]
    pubkey_out: Option<PathBuf>,

    /// Also emit an --add-cfg hjson placing the block into OTP items (single mode).
    #[arg(long, conflicts_with = "manifest")]
    emit_fuse_cfg: Option<PathBuf>,

    /// OTP partition for --emit-fuse-cfg.
    #[arg(long, default_value = "VENDOR_NON_SECRET_PROD_PARTITION")]
    fuse_partition: String,

    /// OTP item name prefix for --emit-fuse-cfg (items are `{prefix}{index}`).
    #[arg(long, default_value = "CPTRA_SS_VENDOR_SPECIFIC_NON_SECRET_FUSE_")]
    fuse_item_prefix: String,

    /// OTP item size in bytes for --emit-fuse-cfg.
    #[arg(long, default_value_t = 32)]
    fuse_item_size: usize,

    /// Index of the first OTP item the block occupies, for --emit-fuse-cfg.
    #[arg(long, default_value_t = 0)]
    fuse_first_index: usize,

    /// Request the partition be locked (SW digest) in the --emit-fuse-cfg output.
    #[arg(long)]
    fuse_lock: bool,
}

fn parse_u32(s: &str) -> Result<u32, String> {
    let s = s.trim();
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    };
    v.map_err(|e| format!("invalid u32 '{s}': {e}"))
}

/// Resolves a resume offset (words) from either an explicit offset or an address.
fn resolve_resume(offset: Option<u16>, addr: Option<u32>, target: u32) -> Result<u16> {
    match (offset, addr) {
        (Some(off), None) => Ok(off),
        (None, Some(addr)) => {
            if addr % 4 != 0 {
                bail!("resume address {addr:#x} is not 4-byte aligned");
            }
            if addr <= target {
                bail!("resume address {addr:#x} must be greater than target {target:#x}");
            }
            u16::try_from((addr - target) / 4)
                .map_err(|_| anyhow::anyhow!("resume offset exceeds the 16-bit field"))
        }
        (None, None) => bail!("a resume_offset or resume_addr is required"),
        (Some(_), Some(_)) => bail!("specify only one of resume_offset / resume_addr"),
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    if let Some(manifest_path) = args.manifest.clone() {
        run_manifest(&manifest_path, &args.out)
    } else {
        run_single(&args)
    }
}

fn run_single(args: &Args) -> Result<()> {
    let target = args.target.expect("required_unless_present manifest");
    let resume_offset = resolve_resume(args.resume_offset, args.resume_addr, target)?;

    let replacement = args.replacement.as_ref().expect("required");
    let signing_key = args.signing_key.as_ref().expect("required");
    let replacement_elf = fs::read(replacement)
        .with_context(|| format!("Failed to read replacement ELF: {}", replacement.display()))?;
    let signer = SeedSigner::from_seed_bytes(
        &fs::read(signing_key)
            .with_context(|| format!("Failed to read signing key: {}", signing_key.display()))?,
    )?;

    let rom_bounds = if let Some(rom_elf) = &args.rom_elf {
        let bytes = fs::read(rom_elf)
            .with_context(|| format!("Failed to read ROM ELF: {}", rom_elf.display()))?;
        RomBounds::ExecRanges(rom_executable_ranges(&bytes)?)
    } else if let (Some(base), Some(size)) = (args.rom_base, args.rom_size) {
        RomBounds::Range { base, size }
    } else {
        RomBounds::Unbounded
    };

    let req = PatchRequest {
        replacement_elf,
        target,
        resume_offset,
        version: args.version,
        critical: args.critical,
        slot_size: args.slot_size,
        rom_bounds,
    };
    let block = build_patch_block(&req, &signer)?;

    fs::write(&args.out, &block)
        .with_context(|| format!("Failed to write patch block: {}", args.out.display()))?;
    println!(
        "Wrote {}-byte signed patch block to {}",
        block.len(),
        args.out.display()
    );

    if let Some(pubkey_out) = &args.pubkey_out {
        fs::write(pubkey_out, signer.public_key()?)
            .with_context(|| format!("Failed to write public key: {}", pubkey_out.display()))?;
        println!(
            "Wrote 32-byte Ed25519 public key to {}",
            pubkey_out.display()
        );
    }

    if let Some(cfg_out) = &args.emit_fuse_cfg {
        let layout = fuse_cfg::FuseLayout {
            partition: args.fuse_partition.clone(),
            item_prefix: args.fuse_item_prefix.clone(),
            item_size: args.fuse_item_size,
            first_index: args.fuse_first_index,
            lock: args.fuse_lock,
        };
        let cfg = fuse_cfg::emit_add_cfg(&block, &layout);
        fs::write(cfg_out, &cfg)
            .with_context(|| format!("Failed to write fuse cfg: {}", cfg_out.display()))?;
        println!(
            "Wrote --add-cfg hjson ({} item(s) of {} B in {}) to {}",
            fuse_cfg::items_for(block.len(), layout.item_size),
            layout.item_size,
            layout.partition,
            cfg_out.display()
        );
    }
    Ok(())
}

fn run_manifest(manifest_path: &Path, out: &Path) -> Result<()> {
    let text = fs::read_to_string(manifest_path)
        .with_context(|| format!("Failed to read manifest: {}", manifest_path.display()))?;
    let m = manifest::parse(&text)?;
    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));

    let signer = SeedSigner::from_seed_bytes(
        &fs::read(base.join(&m.signing_key))
            .with_context(|| format!("Failed to read signing key: {}", m.signing_key))?,
    )?;

    let rom_bounds = match &m.rom_elf {
        Some(rom_elf) => {
            let bytes = fs::read(base.join(rom_elf))
                .with_context(|| format!("Failed to read ROM ELF: {rom_elf}"))?;
            RomBounds::ExecRanges(rom_executable_ranges(&bytes)?)
        }
        None => RomBounds::Unbounded,
    };

    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut placements: Vec<Placement> = Vec::new();
    let mut cursor = 0usize;

    for (i, pe) in m.patches.iter().enumerate() {
        let target =
            manifest::parse_u32(&pe.target).with_context(|| format!("patch {i}: bad target"))?;
        let resume_addr = pe
            .resume_addr
            .as_deref()
            .map(manifest::parse_u32)
            .transpose()
            .with_context(|| format!("patch {i}: bad resume_addr"))?;
        let resume_offset = resolve_resume(pe.resume_offset, resume_addr, target)
            .with_context(|| format!("patch {i} ({})", pe.replacement))?;

        let replacement_elf = fs::read(base.join(&pe.replacement))
            .with_context(|| format!("patch {i}: failed to read {}", pe.replacement))?;
        let req = PatchRequest {
            replacement_elf,
            target,
            resume_offset,
            version: pe.version,
            critical: pe.critical,
            slot_size: None,
            rom_bounds: rom_bounds.clone(),
        };
        let block = build_patch_block(&req, &signer)
            .with_context(|| format!("patch {i} ({})", pe.replacement))?;

        let n_items = fuse_cfg::items_for(block.len(), m.item_size);
        let first_item = pe.slot.unwrap_or(cursor);
        cursor = first_item + n_items;
        placements.push(Placement {
            patch_index: i,
            target,
            first_item,
            n_items,
        });
        blocks.push(block);
    }

    let supersessions = manifest::validate_placements(&placements, m.num_items)?;

    let block_refs: Vec<(usize, &[u8])> = placements
        .iter()
        .map(|p| (p.first_item, blocks[p.patch_index].as_slice()))
        .collect();
    let cfg = fuse_cfg::emit_add_cfg_multi(
        &m.partition,
        &m.item_prefix,
        m.item_size,
        m.lock,
        &block_refs,
    );
    fs::write(out, &cfg).with_context(|| format!("Failed to write {}", out.display()))?;

    println!(
        "Wrote {} patch(es) ({} B items in {}) to {}",
        placements.len(),
        m.item_size,
        m.partition,
        out.display()
    );
    for (p, pe) in placements.iter().zip(&m.patches) {
        println!(
            "  patch {}: target {:#x} -> items [{}..{}) <- {}",
            p.patch_index,
            p.target,
            p.first_item,
            p.first_item + p.n_items,
            pe.replacement
        );
    }
    for s in &supersessions {
        println!(
            "  supersession: target {:#x}: patch {} (higher slot) wins over patch {}",
            s.target, s.winner_patch, s.loser_patch
        );
    }
    Ok(())
}
