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

//! Replacement-ELF loader and patch-ABI enforcement (RFC-0001 §Patch ABI).
//!
//! The replacement is a single, fully-linked, position-independent,
//! relocation-free executable. This module flattens its allocatable sections
//! into a contiguous SRAM image (objcopy-style), enforcing the ABI:
//!
//! - relocation-free (ROM performs no dynamic relocation),
//! - executable code and read-only constants only — no `.data`, `.bss`, TLS,
//!   or other writable/NOBITS allocatable state,
//! - the entry point (`patch_fn`) is at offset 0 of the image (the block format
//!   carries no entry offset).

use anyhow::{bail, ensure, Context, Result};
use goblin::elf::header::{EI_CLASS, EI_DATA, ELFCLASS32, ELFDATA2LSB, EM_RISCV, ET_EXEC};
use goblin::elf::section_header::{
    SHF_ALLOC, SHF_EXECINSTR, SHF_TLS, SHF_WRITE, SHT_NOBITS, SHT_PROGBITS, SHT_REL, SHT_RELA,
};
use goblin::elf::Elf;
use log::debug;

/// Hard cap before flattening section VMAs into a contiguous image.
///
/// Real OTP patch slots are much smaller; this cap prevents malformed ELFs from
/// requesting huge zero-filled gaps before the slot-size validation runs.
const MAX_FLATTENED_IMAGE_BYTES: usize = 1024 * 1024;

/// A flattened replacement code image.
#[derive(Debug, Clone)]
pub struct CodeImage {
    /// Base (lowest) virtual address of the image.
    pub base: u64,
    /// Contiguous image bytes (gaps between sections zero-filled), padded to a
    /// multiple of 4 bytes.
    pub bytes: Vec<u8>,
    /// Executable `(offset, len)` byte ranges within `bytes`, for the CSR scan.
    pub exec_ranges: Vec<(usize, usize)>,
}

/// Extracts the executable `(addr, len)` ranges from a ROM ELF.
///
/// Used to validate that a patch target/resume falls inside real ROM code
/// (`SHF_ALLOC | SHF_EXECINSTR`), not data or an unmapped hole.
pub fn rom_executable_ranges(bytes: &[u8]) -> Result<Vec<(u32, u32)>> {
    let elf = Elf::parse(bytes).context("Failed to parse ROM ELF")?;
    ensure!(
        elf.header.e_machine == EM_RISCV,
        "ROM ELF machine type is {}, expected RISC-V ({})",
        elf.header.e_machine,
        EM_RISCV
    );
    ensure!(
        elf.header.e_ident[EI_CLASS] == ELFCLASS32,
        "ROM ELF must be ELF32/RV32"
    );
    ensure!(
        elf.header.e_ident[EI_DATA] == ELFDATA2LSB,
        "ROM ELF must be little-endian"
    );
    ensure!(
        elf.header.e_type == ET_EXEC,
        "ROM ELF must be a linked executable (ET_EXEC), got e_type {}",
        elf.header.e_type
    );

    let mut ranges = Vec::new();
    for sh in elf.section_headers.iter() {
        let flags = sh.sh_flags as u32;
        if sh.sh_type == SHT_PROGBITS && flags & SHF_ALLOC != 0 && flags & SHF_EXECINSTR != 0 {
            let addr: u32 = sh
                .sh_addr
                .try_into()
                .context("ROM ELF executable section address exceeds 32 bits")?;
            let len: u32 = sh
                .sh_size
                .try_into()
                .context("ROM ELF executable section size exceeds 32 bits")?;
            if len > 0 {
                ranges.push((addr, len));
            }
        }
    }
    ensure!(
        !ranges.is_empty(),
        "ROM ELF has no executable (SHF_EXECINSTR) sections"
    );
    Ok(ranges)
}

/// Parses and flattens a relocation-free replacement ELF into a [`CodeImage`].
pub fn load_replacement(bytes: &[u8]) -> Result<CodeImage> {
    let elf = Elf::parse(bytes).context("Failed to parse replacement ELF")?;

    ensure!(
        !elf.section_headers.is_empty(),
        "No sections in replacement ELF"
    );
    ensure!(
        elf.header.e_machine == EM_RISCV,
        "Replacement ELF machine type is {}, expected RISC-V ({})",
        elf.header.e_machine,
        EM_RISCV
    );
    ensure!(
        elf.header.e_ident[EI_CLASS] == ELFCLASS32,
        "Replacement ELF must be ELF32/RV32"
    );
    ensure!(
        elf.header.e_ident[EI_DATA] == ELFDATA2LSB,
        "Replacement ELF must be little-endian"
    );
    ensure!(
        elf.header.e_type == ET_EXEC,
        "Replacement ELF must be a fully linked executable (ET_EXEC), got e_type {}",
        elf.header.e_type
    );

    // 1) Reject any non-debug relocations (ROM does no dynamic relocation).
    for sh in elf.section_headers.iter() {
        if sh.sh_type == SHT_REL || sh.sh_type == SHT_RELA {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if !(name.starts_with(".rela.debug") || name.starts_with(".rel.debug")) {
                bail!("Replacement ELF contains relocations ({name}); it must be fully linked and relocation-free");
            }
        }
    }

    // 2) Collect allocatable sections, enforcing the ABI.
    struct Seg {
        addr: u64,
        data: Vec<u8>,
        exec: bool,
    }
    let mut segs: Vec<Seg> = Vec::new();

    for sh in elf.section_headers.iter() {
        let flags = sh.sh_flags as u32;
        if flags & SHF_ALLOC == 0 {
            continue; // not loaded into memory
        }
        let name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or("<unknown>")
            .to_string();

        if flags & SHF_TLS != 0 {
            bail!("Replacement ELF has a TLS section ({name}); TLS is not allowed");
        }
        if sh.sh_type == SHT_NOBITS {
            bail!("Replacement ELF has a NOBITS allocatable section ({name}); .bss-style state is not allowed");
        }
        if flags & SHF_WRITE != 0 {
            bail!("Replacement ELF has a writable allocatable section ({name}); .data / mutable globals are not allowed");
        }
        if sh.sh_type != SHT_PROGBITS {
            // Allocatable, read-only, non-PROGBITS (unusual) — skip rather than embed.
            continue;
        }

        let range = sh
            .file_range()
            .context("Failed to get file range of section")?;
        ensure!(
            range.end <= bytes.len(),
            "Replacement ELF section {name} extends past end of file"
        );
        let exec = flags & SHF_EXECINSTR != 0;
        debug!(
            "* include {name} addr={:#x} size={:#x} {}",
            sh.sh_addr,
            sh.sh_size,
            if exec { "code" } else { "rodata" }
        );
        segs.push(Seg {
            addr: sh.sh_addr,
            data: bytes[range].to_vec(),
            exec,
        });
    }

    ensure!(
        !segs.is_empty(),
        "Replacement ELF has no allocatable code/rodata sections"
    );

    // 3) Flatten into a contiguous image [min_addr, max_end).
    let base = segs.iter().map(|s| s.addr).min().unwrap();
    ensure!(
        base % 4 == 0,
        "Replacement image base ({base:#x}) is not 4-byte aligned"
    );
    segs.sort_by_key(|s| s.addr);

    let mut prev_end = None;
    for s in &segs {
        let end = s
            .addr
            .checked_add(s.data.len() as u64)
            .context("Replacement ELF section address overflows")?;
        if let Some(prev) = prev_end {
            ensure!(
                s.addr >= prev,
                "Replacement ELF has overlapping allocatable sections near {:#x}",
                s.addr
            );
        }
        prev_end = Some(end);
    }

    let end = prev_end.unwrap();
    let image_len_u64 = end
        .checked_sub(base)
        .context("Replacement ELF section address range underflows")?;
    let image_len: usize = image_len_u64
        .try_into()
        .context("Replacement ELF image is too large for this host")?;
    ensure!(
        image_len <= MAX_FLATTENED_IMAGE_BYTES,
        "Replacement ELF flattened image is {} bytes, exceeds the {}-byte safety cap",
        image_len,
        MAX_FLATTENED_IMAGE_BYTES
    );
    let mut image = vec![0u8; image_len];
    let mut exec_ranges = Vec::new();

    for s in &segs {
        let off = (s.addr - base) as usize;
        image[off..off + s.data.len()].copy_from_slice(&s.data);
        if s.exec {
            exec_ranges.push((off, s.data.len()));
        }
    }
    ensure!(
        exec_ranges.iter().any(|&(off, len)| off == 0 && len > 0),
        "Replacement image must start with a non-empty executable section"
    );

    // 4) The entry (patch_fn) must be at offset 0 — the block carries no entry
    //    offset, so ROM enters the copied blob at its start.
    ensure!(
        elf.entry == base,
        "Replacement entry point ({:#x}) is not at the image base ({:#x}); patch_fn must be placed first (e.g. ENTRY(patch_fn) and a linker script that emits it at the lowest address)",
        elf.entry,
        base
    );

    // 5) Pad image to a 4-byte (word) multiple.
    if image.len() % 4 != 0 {
        image.resize(image.len().div_ceil(4) * 4, 0);
    }

    Ok(CodeImage {
        base,
        bytes: image,
        exec_ranges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_elf::{
        build_elf32, riscv_replacement, Section, ELFDATA2LSB, ELFDATA2MSB, EM_RISCV, NOP_WORD,
        SHF_ALLOC, SHF_TLS, SHF_WRITE, SHT_NOBITS, SHT_RELA,
    };

    fn err_of(elf: &[u8]) -> String {
        load_replacement(elf).unwrap_err().to_string()
    }

    #[test]
    fn loads_a_valid_replacement() {
        let img = load_replacement(&riscv_replacement(0x1000, &NOP_WORD)).unwrap();
        assert_eq!(img.base, 0x1000);
        assert_eq!(img.bytes, NOP_WORD);
        assert_eq!(img.exec_ranges, vec![(0, 4)]);
    }

    #[test]
    fn rom_executable_ranges_collects_exec_sections_only() {
        let rom = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x8000,
            &[
                Section::code(".text", 0x8000, &[0u8; 0x40]),
                Section::rodata(".rodata", 0x9000, &[0u8; 0x10]), // not executable
            ],
        );
        assert_eq!(rom_executable_ranges(&rom).unwrap(), vec![(0x8000, 0x40)]);
    }

    #[test]
    fn rom_executable_ranges_errors_without_code() {
        let rom = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x8000,
            &[Section::rodata(".rodata", 0x8000, &[0u8; 0x10])],
        );
        assert!(rom_executable_ranges(&rom).is_err());
    }

    #[test]
    fn rom_executable_ranges_rejects_wrong_elf_identity() {
        let mut rom = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x8000,
            &[Section::code(".text", 0x8000, &[0u8; 0x40])],
        );
        // ELF e_type is a little-endian u16 at bytes 16..18. 1 is ET_REL.
        rom[16..18].copy_from_slice(&1u16.to_le_bytes());
        assert!(rom_executable_ranges(&rom)
            .unwrap_err()
            .to_string()
            .contains("ET_EXEC"));
    }

    #[test]
    fn flattens_code_and_rodata_with_gap() {
        // .text at 0x1000 (4 B), .rodata at 0x1008 (4 B) -> 12-byte image, gap zeroed.
        let elf = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x1000,
            &[
                Section::code(".text", 0x1000, &NOP_WORD),
                Section::rodata(".rodata", 0x1008, &[1, 2, 3, 4]),
            ],
        );
        let img = load_replacement(&elf).unwrap();
        assert_eq!(img.bytes.len(), 12);
        assert_eq!(img.exec_ranges, vec![(0, 4)]);
        assert_eq!(&img.bytes[4..8], &[0, 0, 0, 0]); // rodata included; gap zero-filled
    }

    #[test]
    fn rejects_rodata_only_image() {
        let elf = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x1000,
            &[Section::rodata(".rodata", 0x1000, &[1, 2, 3, 4])],
        );
        assert!(err_of(&elf).contains("executable section"));
    }

    #[test]
    fn rejects_non_riscv_machine() {
        let elf = build_elf32(
            62, /* x86-64 */
            ELFDATA2LSB,
            0x1000,
            &[Section::code(".text", 0x1000, &NOP_WORD)],
        );
        assert!(err_of(&elf).contains("expected RISC-V"));
    }

    #[test]
    fn rejects_non_executable_elf_type() {
        let mut elf = riscv_replacement(0x1000, &NOP_WORD);
        // ELF e_type is a little-endian u16 at bytes 16..18. 1 is ET_REL.
        elf[16..18].copy_from_slice(&1u16.to_le_bytes());
        assert!(err_of(&elf).contains("ET_EXEC"));
    }

    #[test]
    fn rejects_big_endian() {
        let elf = build_elf32(
            EM_RISCV,
            ELFDATA2MSB,
            0x1000,
            &[Section::code(".text", 0x1000, &NOP_WORD)],
        );
        assert!(err_of(&elf).contains("little-endian"));
    }

    #[test]
    fn rejects_writable_section() {
        let mut data = Section::rodata(".data", 0x1004, &[0, 0, 0, 0]);
        data.sh_flags = SHF_ALLOC | SHF_WRITE;
        let elf = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x1000,
            &[Section::code(".text", 0x1000, &NOP_WORD), data],
        );
        assert!(err_of(&elf).contains("writable"));
    }

    #[test]
    fn rejects_nobits_bss() {
        let bss = Section {
            name: ".bss",
            sh_type: SHT_NOBITS,
            sh_flags: SHF_ALLOC | SHF_WRITE,
            sh_addr: 0x1004,
            data: Vec::new(),
            sh_size: Some(8),
        };
        let elf = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x1000,
            &[Section::code(".text", 0x1000, &NOP_WORD), bss],
        );
        assert!(err_of(&elf).contains("NOBITS"));
    }

    #[test]
    fn rejects_tls() {
        let mut tls = Section::rodata(".tdata", 0x1004, &[0, 0, 0, 0]);
        tls.sh_flags = SHF_ALLOC | SHF_TLS;
        let elf = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x1000,
            &[Section::code(".text", 0x1000, &NOP_WORD), tls],
        );
        assert!(err_of(&elf).contains("TLS"));
    }

    #[test]
    fn rejects_relocations() {
        let rela = Section {
            name: ".rela.text",
            sh_type: SHT_RELA,
            sh_flags: 0,
            sh_addr: 0,
            data: Vec::new(),
            sh_size: None,
        };
        let elf = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x1000,
            &[Section::code(".text", 0x1000, &NOP_WORD), rela],
        );
        assert!(err_of(&elf).contains("relocations"));
    }

    #[test]
    fn rejects_entry_not_at_base() {
        // .text at 0x1000 but entry declared at 0x1004.
        let elf = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x1004,
            &[Section::code(".text", 0x1000, &NOP_WORD)],
        );
        assert!(err_of(&elf).contains("entry point"));
    }

    #[test]
    fn rejects_overlapping_sections() {
        let elf = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x1000,
            &[
                Section::code(".text", 0x1000, &[0u8; 8]),
                Section::code(".text2", 0x1004, &[0u8; 8]), // overlaps 0x1004..0x1008
            ],
        );
        assert!(err_of(&elf).contains("overlapping"));
    }

    #[test]
    fn rejects_unaligned_base() {
        let elf = build_elf32(
            EM_RISCV,
            ELFDATA2LSB,
            0x1002,
            &[Section::code(".text", 0x1002, &NOP_WORD)],
        );
        assert!(err_of(&elf).contains("4-byte aligned"));
    }
}
