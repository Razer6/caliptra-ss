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

//! Minimal ELF32 builder for hermetic tests.
//!
//! Lets the unit tests construct exactly the replacement ELFs they need —
//! valid and malformed — without a RISC-V toolchain or committed binary
//! fixtures. Produces a little-endian ELF32 with a section header table and a
//! `.shstrtab`; program headers are omitted (the loader only reads sections).

// e_machine
pub const EM_RISCV: u16 = 243;
// e_type
pub const ET_EXEC: u16 = 2;
// EI_DATA
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;
// sh_type
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOBITS: u32 = 8;
// sh_flags
pub const SHF_WRITE: u32 = 0x1;
pub const SHF_ALLOC: u32 = 0x2;
pub const SHF_EXECINSTR: u32 = 0x4;
pub const SHF_TLS: u32 = 0x400;

/// RV32 `addi x0, x0, 0` (canonical 32-bit NOP) — not a `SYSTEM` instruction.
pub const NOP_WORD: [u8; 4] = [0x13, 0x00, 0x00, 0x00];

const ELF_HEADER_SIZE: usize = 52;
const SH_ENTRY_SIZE: usize = 40;

/// A section to place in the test ELF.
pub struct Section {
    pub name: &'static str,
    pub sh_type: u32,
    pub sh_flags: u32,
    pub sh_addr: u32,
    pub data: Vec<u8>,
    /// Override `sh_size` (e.g. for `SHT_NOBITS`); defaults to `data.len()`.
    pub sh_size: Option<u32>,
}

impl Section {
    /// An allocatable executable code section.
    pub fn code(name: &'static str, addr: u32, data: &[u8]) -> Self {
        Self {
            name,
            sh_type: SHT_PROGBITS,
            sh_flags: SHF_ALLOC | SHF_EXECINSTR,
            sh_addr: addr,
            data: data.to_vec(),
            sh_size: None,
        }
    }

    /// An allocatable read-only data section.
    pub fn rodata(name: &'static str, addr: u32, data: &[u8]) -> Self {
        Self {
            name,
            sh_type: SHT_PROGBITS,
            sh_flags: SHF_ALLOC,
            sh_addr: addr,
            data: data.to_vec(),
            sh_size: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_sh(
    buf: &mut Vec<u8>,
    be: bool,
    name: u32,
    sh_type: u32,
    flags: u32,
    addr: u32,
    offset: u32,
    size: u32,
    addralign: u32,
) {
    let w = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    buf.extend_from_slice(&w(name));
    buf.extend_from_slice(&w(sh_type));
    buf.extend_from_slice(&w(flags));
    buf.extend_from_slice(&w(addr));
    buf.extend_from_slice(&w(offset));
    buf.extend_from_slice(&w(size));
    buf.extend_from_slice(&w(0)); // sh_link
    buf.extend_from_slice(&w(0)); // sh_info
    buf.extend_from_slice(&w(addralign));
    buf.extend_from_slice(&w(0)); // sh_entsize
}

/// Builds an ELF32 image from `sections`, honouring `e_ident_data` byte order.
pub fn build_elf32(e_machine: u16, e_ident_data: u8, entry: u32, sections: &[Section]) -> Vec<u8> {
    let be = e_ident_data == ELFDATA2MSB;
    let h16 = |v: u16| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    let h32 = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    // Section header string table: index 0 is the empty name.
    let mut shstrtab = vec![0u8];
    let mut name_offs = Vec::with_capacity(sections.len());
    for s in sections {
        name_offs.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(s.name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_name = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    // File offsets for section payloads, after the ELF header.
    let mut off = ELF_HEADER_SIZE;
    let mut data_offs = Vec::with_capacity(sections.len());
    for s in sections {
        if s.data.is_empty() {
            data_offs.push(0);
        } else {
            data_offs.push(off as u32);
            off += s.data.len();
        }
    }
    let shstrtab_off = off;
    off += shstrtab.len();
    let pad = (4 - off % 4) % 4;
    off += pad;
    let shoff = off;

    let shnum = (sections.len() + 2) as u16; // null + sections + shstrtab
    let shstrndx = (sections.len() + 1) as u16;

    let mut buf = Vec::with_capacity(shoff + shnum as usize * SH_ENTRY_SIZE);

    // ELF header.
    buf.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf.push(1); // EI_CLASS = ELFCLASS32
    buf.push(e_ident_data); // EI_DATA
    buf.push(1); // EI_VERSION
    buf.extend_from_slice(&[0u8; 9]); // pad to EI_NIDENT (16)
    buf.extend_from_slice(&h16(ET_EXEC));
    buf.extend_from_slice(&h16(e_machine));
    buf.extend_from_slice(&h32(1)); // e_version
    buf.extend_from_slice(&h32(entry));
    buf.extend_from_slice(&h32(0)); // e_phoff
    buf.extend_from_slice(&h32(shoff as u32));
    buf.extend_from_slice(&h32(0)); // e_flags
    buf.extend_from_slice(&h16(ELF_HEADER_SIZE as u16));
    buf.extend_from_slice(&h16(0)); // e_phentsize
    buf.extend_from_slice(&h16(0)); // e_phnum
    buf.extend_from_slice(&h16(SH_ENTRY_SIZE as u16));
    buf.extend_from_slice(&h16(shnum));
    buf.extend_from_slice(&h16(shstrndx));
    assert_eq!(buf.len(), ELF_HEADER_SIZE);

    // Section payloads, then shstrtab, then padding to shoff.
    for s in sections {
        buf.extend_from_slice(&s.data);
    }
    buf.extend_from_slice(&shstrtab);
    buf.extend(std::iter::repeat(0).take(pad));
    assert_eq!(buf.len(), shoff);

    // Section header table: null entry, sections, then shstrtab.
    push_sh(&mut buf, be, 0, 0, 0, 0, 0, 0, 0);
    for (i, s) in sections.iter().enumerate() {
        let size = s.sh_size.unwrap_or(s.data.len() as u32);
        push_sh(
            &mut buf,
            be,
            name_offs[i],
            s.sh_type,
            s.sh_flags,
            s.sh_addr,
            data_offs[i],
            size,
            4,
        );
    }
    push_sh(
        &mut buf,
        be,
        shstrtab_name,
        3, // SHT_STRTAB
        0,
        0,
        shstrtab_off as u32,
        shstrtab.len() as u32,
        1,
    );

    buf
}

/// A minimal valid RV32 replacement: one `.text` section at `base`, entry at
/// `base`, containing `code`.
pub fn riscv_replacement(base: u32, code: &[u8]) -> Vec<u8> {
    build_elf32(
        EM_RISCV,
        ELFDATA2LSB,
        base,
        &[Section::code(".text", base, code)],
    )
}
