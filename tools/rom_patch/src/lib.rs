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

//! Caliptra MCU ROM patch packer (RFC-0001 / caliptra-ss#1163).
//!
//! Produces a signed binary patch block from a pre-built, relocation-free
//! replacement ELF, for the PMP trap-and-patch model. This is the Rust half of
//! the toolchain; OTP partition image generation is handed off to caliptra-ss's
//! Python fuse tooling (see `docs/DESIGN.md`).
//!
//! Pipeline: [`elf::load_replacement`] → [`csr_scan::scan_executable`] +
//! [`abi::AbiPolicy`] → validation → [`block::pack_and_sign`].

pub mod abi;
pub mod block;
pub mod csr_scan;
pub mod elf;
pub mod fuse_cfg;
pub mod manifest;
pub mod signer;

#[cfg(test)]
pub(crate) mod test_elf;

use anyhow::{bail, ensure, Context, Result};
use log::{info, warn};

use abi::AbiPolicy;
use block::{BlockParams, CODE_OFFSET};
use signer::PatchSigner;

/// Constraint on where the target/resume addresses may fall in the ROM.
#[derive(Debug, Clone)]
pub enum RomBounds {
    /// No ROM constraint; the in-range check is skipped (and logged).
    Unbounded,
    /// A numeric ROM address window `[base, base + size)`.
    Range { base: u32, size: u32 },
    /// Executable `(addr, len)` ranges parsed from the ROM ELF. The target and
    /// resume addresses must each fall within an executable ROM section.
    ExecRanges(Vec<(u32, u32)>),
}

impl RomBounds {
    /// Whether `addr` satisfies the bound.
    fn allows(&self, addr: u32) -> Result<bool> {
        Ok(match self {
            RomBounds::Unbounded => true,
            RomBounds::Range { base, size } => {
                let end = base
                    .checked_add(*size)
                    .context("ROM range base+size overflows")?;
                addr >= *base && addr < end
            }
            RomBounds::ExecRanges(ranges) => ranges.iter().any(|&(a, len)| {
                a.checked_add(len)
                    .is_some_and(|end| addr >= a && addr < end)
            }),
        })
    }
}

/// A request to build one signed patch block.
#[derive(Debug, Clone)]
pub struct PatchRequest {
    /// Raw bytes of the pre-built, relocation-free replacement ELF.
    pub replacement_elf: Vec<u8>,
    /// Absolute target ROM address (4-byte aligned).
    pub target: u32,
    /// Resume offset in 4-byte words from `target` (non-zero).
    pub resume_offset: u16,
    /// Patch format / ABI version (header bits 23:16).
    pub version: u8,
    /// `CRITICAL` flag.
    pub critical: bool,
    /// Total OTP slot size in bytes, if the code-fits check should run. Code is
    /// bounded to `slot_size - 0x4C` (signature + header prefix).
    pub slot_size: Option<usize>,
    /// Constraint on target/resume addresses against the ROM.
    pub rom_bounds: RomBounds,
}

/// Builds and signs a patch block from a [`PatchRequest`].
pub fn build_patch_block(req: &PatchRequest, signer: &dyn PatchSigner) -> Result<Vec<u8>> {
    // 1) Flatten the replacement ELF and enforce the patch ABI.
    let image =
        elf::load_replacement(&req.replacement_elf).context("Failed to load replacement ELF")?;
    info!(
        "Replacement image: base={:#x}, {} bytes ({} words), {} executable range(s)",
        image.base,
        image.bytes.len(),
        image.bytes.len() / 4,
        image.exec_ranges.len()
    );

    // 2) ABI scan. The scanner decodes ISA facts from executable sections
    //    (exact RV32IMC walk); the version-keyed policy decides what is allowed.
    //    Read-only data is carried in the signed image but is not scanned as
    //    code; byte-pattern scanning would reject valid constants that happen to
    //    equal a forbidden instruction encoding.
    let policy = AbiPolicy::for_version(req.version)?;
    let findings = csr_scan::scan_executable(&image.bytes, &image.exec_ranges)
        .context("Failed to scan replacement executable code")?;

    let bad_csr: Vec<_> = findings
        .csr_writes
        .iter()
        .filter(|w| !policy.csr_write_allowed(w.csr))
        .collect();
    if !bad_csr.is_empty() {
        let mut msg = String::from("Replacement performs CSR write(s) not allowed by the ABI:");
        for w in &bad_csr {
            msg.push_str(&format!(
                "\n  - {} to CSR {:#05x} at image offset {:#x}",
                w.mnemonic, w.csr, w.offset
            ));
        }
        bail!(
            "{msg}\n(patch ABI v{} allowlists no CSR writes)",
            policy.version
        );
    }

    let bad_priv: Vec<_> = findings
        .priv_instrs
        .iter()
        .filter(|p| policy.is_forbidden(p.kind))
        .collect();
    if !bad_priv.is_empty() {
        let mut msg =
            String::from("Replacement contains instruction(s) forbidden by the patch ABI:");
        for p in &bad_priv {
            msg.push_str(&format!(
                "\n  - {} at image offset {:#x}",
                p.kind.mnemonic(),
                p.offset
            ));
        }
        bail!("{msg}\nreplacement code must return to the trap handler with ret");
    }
    info!(
        "ABI v{} scan passed (no disallowed CSR writes or forbidden instructions)",
        policy.version
    );

    let resume_addr = req
        .target
        .checked_add(u32::from(req.resume_offset) * 4)
        .context("resume address overflows u32")?;

    // 3) ROM bounds check: target and resume must lie within the ROM (or, with
    //    an ELF, within an executable ROM section).
    match &req.rom_bounds {
        RomBounds::Unbounded => warn!("No ROM bounds provided; skipping target/resume range check"),
        bounds => {
            let what = match bounds {
                RomBounds::ExecRanges(_) => "an executable ROM section",
                _ => "the ROM range",
            };
            ensure!(
                bounds.allows(req.target)?,
                "target {:#x} is not within {what}",
                req.target
            );
            ensure!(
                bounds.allows(resume_addr)?,
                "resume address {:#x} is not within {what}",
                resume_addr
            );
        }
    }

    // 4) Slot-capacity bound on the code.
    let max_code_bytes = match req.slot_size {
        Some(slot) => {
            ensure!(
                slot > CODE_OFFSET,
                "slot size {slot} is too small for the {CODE_OFFSET}-byte header prefix"
            );
            Some(slot - CODE_OFFSET)
        }
        None => None,
    };

    // 5) Pack and sign.
    let params = BlockParams {
        version: req.version,
        critical: req.critical,
        target: req.target,
        resume_offset: req.resume_offset,
        code: image.bytes,
    };
    let block = block::pack_and_sign(&params, signer, max_code_bytes)
        .context("Failed to pack and sign the patch block")?;

    info!(
        "Patch block: {} bytes (sig 64 + header 12 + code {}), target={:#x}, resume_offset={}, critical={}",
        block.len(),
        params.code_words() as usize * 4,
        req.target,
        req.resume_offset,
        req.critical
    );
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SeedSigner;
    use crate::test_elf::{riscv_replacement, NOP_WORD};
    use ed25519_dalek::{Signature, VerifyingKey};

    fn test_key() -> SeedSigner {
        SeedSigner::from_seed_bytes(&[9u8; 32]).unwrap()
    }

    fn sample_request() -> PatchRequest {
        PatchRequest {
            // entry at base 0x1000; one NOP word of replacement code.
            replacement_elf: riscv_replacement(0x1000, &NOP_WORD),
            target: 0x1000,
            resume_offset: 1,
            version: 1,
            critical: false,
            slot_size: Some(256),
            rom_bounds: RomBounds::Range {
                base: 0x1000,
                size: 0x100,
            },
        }
    }

    #[test]
    fn builds_and_signs_a_minimal_patch() {
        let key = test_key();
        let block = build_patch_block(&sample_request(), &key).unwrap();

        // Layout: 64-byte sig + 12-byte header + 4-byte code.
        assert_eq!(block.len(), 64 + 12 + 4);
        // Signature verifies over the payload (0x40..end).
        let vk = VerifyingKey::from_bytes(&key.public_key().unwrap()).unwrap();
        let sig = Signature::from_bytes(block[..64].try_into().unwrap());
        assert!(vk.verify_strict(&block[0x40..], &sig).is_ok());
    }

    #[test]
    fn rejects_resume_address_outside_rom_range() {
        let mut req = sample_request();
        req.rom_bounds = RomBounds::Range {
            base: 0x1000,
            size: 4,
        }; // resume 0x1004 out
        let err = build_patch_block(&req, &test_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("resume address"), "{err}");
    }

    #[test]
    fn rejects_target_outside_rom_range() {
        let mut req = sample_request();
        req.rom_bounds = RomBounds::Range {
            base: 0x2000,
            size: 0x100,
        };
        let err = build_patch_block(&req, &test_key())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("target") && err.contains("not within"),
            "{err}"
        );
    }

    #[test]
    fn accepts_target_in_executable_rom_section() {
        let mut req = sample_request();
        req.rom_bounds = RomBounds::ExecRanges(vec![(0x1000, 0x40)]); // covers 0x1000 & 0x1004
        assert!(build_patch_block(&req, &test_key()).is_ok());
    }

    #[test]
    fn rejects_target_outside_executable_rom_sections() {
        let mut req = sample_request();
        // target 0x1000 sits before the only executable section.
        req.rom_bounds = RomBounds::ExecRanges(vec![(0x2000, 0x40)]);
        let err = build_patch_block(&req, &test_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("executable ROM section"), "{err}");
    }

    #[test]
    fn rejects_ebreak_in_replacement() {
        let mut req = sample_request();
        req.replacement_elf = riscv_replacement(0x1000, &0x0010_0073u32.to_le_bytes()); // ebreak
        let err = build_patch_block(&req, &test_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("ebreak") && err.contains("forbidden"), "{err}");
    }

    #[test]
    fn allows_ecall_in_replacement() {
        // ecall is decoded but not forbidden by ABI v1.
        let mut req = sample_request();
        req.replacement_elf = riscv_replacement(0x1000, &0x0000_0073u32.to_le_bytes()); // ecall
        assert!(build_patch_block(&req, &test_key()).is_ok());
    }

    #[test]
    fn rejects_unsupported_abi_version() {
        let mut req = sample_request();
        req.version = 2;
        let err = build_patch_block(&req, &test_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported patch ABI version"), "{err}");
    }
}
