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

//! Patch-set manifest (hjson) — multiple patches into one OTP partition image.
//!
//! The per-block packer is stateless; this layer composes a *set* of patches,
//! assigns each to OTP item slots, validates the set, and (via
//! [`crate::fuse_cfg::emit_add_cfg_multi`]) emits one combined `--add-cfg`.
//!
//! Ordering rules it enforces / reports (RFC-0001):
//! - Patches on **different** targets are independent — relative order is moot.
//! - Two patches on the **same** target are *supersession*: the one in the
//!   **higher** OTP slot wins at ROM boot. This module reports that map; it does
//!   not pick a winner (ROM does), but it flags it so it's intentional.
//! - Blocks must not overlap in OTP item space (a hard error).
//!
//! Format is hjson (comments, unquoted keys) to match caliptra-ss tooling.
//! Example:
//! ```hjson
//! {
//!   signing_key: "ed25519_seed.bin"   // raw 32-byte seed
//!   rom_elf: "mcu-rom.elf"            // optional; validates target/resume
//!   item_size: 32                     // OTP item size (bytes)
//!   num_items: 64                     // optional capacity check
//!   patches: [
//!     { replacement: "pll_fix.elf", target: "0x1040", resume_offset: 1, slot: 0 }
//!     { replacement: "gpio_fix.elf", target: "0x2000", resume_addr: "0x2008" }
//!   ]
//! }
//! ```

use anyhow::{bail, Context, Result};
use serde::Deserialize;

fn default_partition() -> String {
    "VENDOR_NON_SECRET_PROD_PARTITION".to_string()
}
fn default_item_prefix() -> String {
    "CPTRA_SS_VENDOR_SPECIFIC_NON_SECRET_FUSE_".to_string()
}
fn default_item_size() -> usize {
    32
}
fn default_version() -> u8 {
    1
}

/// A patch-set manifest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Path to the raw 32-byte Ed25519 seed (relative to the manifest file).
    pub signing_key: String,
    /// Optional ROM ELF; if set, every patch's target/resume is checked to fall
    /// in an executable ROM section.
    #[serde(default)]
    pub rom_elf: Option<String>,
    /// OTP partition name.
    #[serde(default = "default_partition")]
    pub partition: String,
    /// OTP item name prefix.
    #[serde(default = "default_item_prefix")]
    pub item_prefix: String,
    /// OTP item size in bytes.
    #[serde(default = "default_item_size")]
    pub item_size: usize,
    /// Optional number of items in the partition (capacity check).
    #[serde(default)]
    pub num_items: Option<usize>,
    /// Request the partition be locked (SW digest) in the emitted cfg.
    #[serde(default)]
    pub lock: bool,
    /// The patches.
    pub patches: Vec<PatchEntry>,
}

/// One patch in the set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchEntry {
    /// Path to the pre-built replacement ELF (relative to the manifest file).
    pub replacement: String,
    /// Target ROM address, `0x`-hex or decimal string.
    pub target: String,
    /// Resume offset in words (mutually exclusive with `resume_addr`).
    #[serde(default)]
    pub resume_offset: Option<u16>,
    /// Resume address, `0x`-hex or decimal string (mutually exclusive).
    #[serde(default)]
    pub resume_addr: Option<String>,
    /// Patch ABI version.
    #[serde(default = "default_version")]
    pub version: u8,
    /// `CRITICAL` flag.
    #[serde(default)]
    pub critical: bool,
    /// First OTP item index this block occupies. If omitted, slots are assigned
    /// sequentially after the previous patch.
    #[serde(default)]
    pub slot: Option<usize>,
}

/// Parses an hjson manifest.
pub fn parse(text: &str) -> Result<Manifest> {
    let m: Manifest = deser_hjson::from_str(text).context("Failed to parse hjson manifest")?;
    if m.patches.is_empty() {
        bail!("manifest has no patches");
    }
    if m.item_size == 0 {
        bail!("item_size must be non-zero");
    }
    Ok(m)
}

/// Parses a `0x`-hex or decimal address string.
pub fn parse_u32(s: &str) -> Result<u32> {
    let s = s.trim();
    let v = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => s.parse::<u32>(),
    };
    v.with_context(|| format!("invalid u32 '{s}'"))
}

/// A block placed in OTP item space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// Index into the manifest's `patches`.
    pub patch_index: usize,
    /// Target ROM address.
    pub target: u32,
    /// First OTP item index.
    pub first_item: usize,
    /// Number of items occupied.
    pub n_items: usize,
}

/// A same-target supersession: `superseded_by` (higher slot) wins over `loser`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supersession {
    pub target: u32,
    pub winner_patch: usize,
    pub loser_patch: usize,
}

/// Validates the set: no OTP item-range overlap, fits `num_items` if given.
/// Returns the supersession relations (same-target, higher slot wins) for
/// reporting — these are intentional, not errors.
pub fn validate_placements(
    placements: &[Placement],
    num_items: Option<usize>,
) -> Result<Vec<Supersession>> {
    // 1) OTP item-range overlap is a hard error.
    let mut by_item: Vec<&Placement> = placements.iter().collect();
    by_item.sort_by_key(|p| p.first_item);
    for w in by_item.windows(2) {
        let (a, b) = (w[0], w[1]);
        let a_end = a.first_item + a.n_items;
        if b.first_item < a_end {
            bail!(
                "patches {} and {} occupy overlapping OTP items ([{}..{}) and [{}..{}))",
                a.patch_index,
                b.patch_index,
                a.first_item,
                a_end,
                b.first_item,
                b.first_item + b.n_items
            );
        }
    }

    // 2) Capacity.
    if let Some(cap) = num_items {
        if let Some(max) = placements.iter().map(|p| p.first_item + p.n_items).max() {
            if max > cap {
                bail!("patch set needs {max} OTP items but the partition has only {cap}");
            }
        }
    }

    // 3) Same-target supersession (higher slot wins). Reported, not an error.
    let mut supersessions = Vec::new();
    for (i, a) in placements.iter().enumerate() {
        for b in &placements[i + 1..] {
            if a.target == b.target {
                let (winner, loser) = if a.first_item >= b.first_item {
                    (a, b)
                } else {
                    (b, a)
                };
                supersessions.push(Supersession {
                    target: a.target,
                    winner_patch: winner.patch_index,
                    loser_patch: loser.patch_index,
                });
            }
        }
    }
    Ok(supersessions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(idx: usize, target: u32, first: usize, n: usize) -> Placement {
        Placement {
            patch_index: idx,
            target,
            first_item: first,
            n_items: n,
        }
    }

    #[test]
    fn parses_minimal_manifest() {
        let m = parse(
            r#"{
                signing_key: "k.bin"
                patches: [
                    { replacement: "a.elf", target: "0x1040", resume_offset: 1 }
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(m.item_size, 32); // default
        assert_eq!(m.partition, "VENDOR_NON_SECRET_PROD_PARTITION");
        assert_eq!(m.patches.len(), 1);
        assert_eq!(m.patches[0].target, "0x1040");
    }

    #[test]
    fn rejects_unknown_field() {
        assert!(parse(r#"{ signing_key:"k", bogus:1, patches:[] }"#).is_err());
    }

    #[test]
    fn parse_u32_hex_and_dec() {
        assert_eq!(parse_u32("0x1040").unwrap(), 0x1040);
        assert_eq!(parse_u32("4160").unwrap(), 4160);
        assert!(parse_u32("zzz").is_err());
    }

    #[test]
    fn detects_otp_overlap() {
        let ps = [p(0, 0x1000, 0, 3), p(1, 0x2000, 2, 1)]; // [0..3) and [2..3) overlap
        assert!(validate_placements(&ps, None).is_err());
    }

    #[test]
    fn allows_adjacent_and_reports_supersession() {
        // patch0 target X at items [0..3); patch1 same target X at [3..6) -> supersedes.
        let ps = [p(0, 0x1000, 0, 3), p(1, 0x1000, 3, 3)];
        let s = validate_placements(&ps, Some(6)).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].winner_patch, 1); // higher slot wins
        assert_eq!(s[0].loser_patch, 0);
    }

    #[test]
    fn distinct_targets_are_independent() {
        let ps = [p(0, 0x1000, 0, 2), p(1, 0x2000, 2, 2)];
        assert!(validate_placements(&ps, None).unwrap().is_empty());
    }

    #[test]
    fn enforces_capacity() {
        let ps = [p(0, 0x1000, 0, 3), p(1, 0x2000, 3, 3)];
        assert!(validate_placements(&ps, Some(5)).is_err()); // needs 6
        assert!(validate_placements(&ps, Some(6)).is_ok());
    }
}
