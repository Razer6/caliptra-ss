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

//! RV32IMC executable scanner — a pure ISA decoder (RFC-0001 §CSR Allowlist).
//!
//! This module reports *facts* about the replacement's executable code:
//! semantic CSR writes and privileged `SYSTEM` instructions. It does **not**
//! decide what is allowed — that is the patch ABI's job (see [`crate::abi`]),
//! which lets a kind (e.g. `ecall`) be recognised here yet permitted by policy.
//!
//! CSR write classification follows the standard RISC-V ISA rules:
//! - `csrrw` / `csrrwi`  : always a write (regardless of `rd`).
//! - `csrrs` / `csrrsi`  : write (set bits) iff the `rs1`/`uimm` field != 0.
//! - `csrrc` / `csrrci`  : write (clear bits) iff the `rs1`/`uimm` field != 0.
//!
//! Instruction boundaries are resolved with an exact RV32IMC length walk: the
//! low two bits of the first halfword distinguish a 16-bit compressed
//! instruction (`!= 0b11`) from a 32-bit instruction (`== 0b11`). RVC has no
//! CSR or privileged `SYSTEM` instructions, so every such access is a 32-bit
//! `SYSTEM` (opcode `0x73`) instruction. This is exact for RV32IMC and avoids
//! the false positives a naive 4-byte window scan would produce on compressed
//! code.

use anyhow::{bail, Result};

const OPCODE_SYSTEM: u32 = 0x73;

/// A privileged / trap-altering `SYSTEM` instruction recognised by the decoder.
///
/// Recognition is ISA-level; whether a given kind is *forbidden* is decided per
/// ABI version by [`crate::abi::AbiPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivKind {
    Ecall,
    Ebreak,
    Wfi,
    Mret,
    Sret,
    Dret,
}

impl PrivKind {
    /// The assembly mnemonic.
    pub fn mnemonic(self) -> &'static str {
        match self {
            PrivKind::Ecall => "ecall",
            PrivKind::Ebreak => "ebreak",
            PrivKind::Wfi => "wfi",
            PrivKind::Mret => "mret",
            PrivKind::Sret => "sret",
            PrivKind::Dret => "dret",
        }
    }
}

/// A semantic CSR write found in the replacement code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrWrite {
    /// Byte offset of the instruction within the code image.
    pub offset: usize,
    /// CSR number (12-bit immediate field).
    pub csr: u16,
    /// Mnemonic of the instruction.
    pub mnemonic: &'static str,
}

/// A privileged `SYSTEM` instruction found in the replacement code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivInstr {
    /// Byte offset of the instruction within the code image.
    pub offset: usize,
    /// Which privileged instruction.
    pub kind: PrivKind,
}

/// Facts decoded from the executable ranges of a code image.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScanFindings {
    /// Semantic CSR writes.
    pub csr_writes: Vec<CsrWrite>,
    /// Privileged `SYSTEM` instructions.
    pub priv_instrs: Vec<PrivInstr>,
}

/// If `word` is a CSR instruction, returns `(is_semantic_write, mnemonic)`.
fn classify_csr(word: u32) -> Option<(bool, &'static str)> {
    let funct3 = (word >> 12) & 0x7;
    // For both register and immediate forms this field is rs1 / zimm[4:0].
    let rs1_or_uimm = (word >> 15) & 0x1f;
    match funct3 {
        0b001 => Some((true, "csrrw")),
        0b101 => Some((true, "csrrwi")),
        0b010 => Some((rs1_or_uimm != 0, "csrrs")),
        0b011 => Some((rs1_or_uimm != 0, "csrrc")),
        0b110 => Some((rs1_or_uimm != 0, "csrrsi")),
        0b111 => Some((rs1_or_uimm != 0, "csrrci")),
        _ => None, // funct3 == 0: ecall/ebreak/mret/... handled by privileged_kind
    }
}

/// If `word` is a recognised privileged `SYSTEM` instruction, returns its kind.
fn privileged_kind(word: u32) -> Option<PrivKind> {
    match word {
        0x0000_0073 => Some(PrivKind::Ecall),
        0x0010_0073 => Some(PrivKind::Ebreak),
        0x1050_0073 => Some(PrivKind::Wfi),
        0x3020_0073 => Some(PrivKind::Mret),
        0x1020_0073 => Some(PrivKind::Sret),
        0x7b20_0073 => Some(PrivKind::Dret),
        _ => None,
    }
}

fn decode_system(word: u32, offset: usize, out: &mut ScanFindings) {
    if word & 0x7f != OPCODE_SYSTEM {
        return;
    }
    if let Some((is_write, mnemonic)) = classify_csr(word) {
        if is_write {
            out.csr_writes.push(CsrWrite {
                offset,
                csr: ((word >> 20) & 0xfff) as u16,
                mnemonic,
            });
        }
    }
    if let Some(kind) = privileged_kind(word) {
        out.priv_instrs.push(PrivInstr { offset, kind });
    }
}

/// Decodes the executable byte ranges of a code image into [`ScanFindings`].
///
/// `ranges` is a list of `(offset, len)` byte ranges within `image` flagged
/// executable (`SHF_EXECINSTR`); only those are walked, as exact RV32IMC
/// instruction streams. Read-only data is not scanned.
///
/// Errors only on a malformed instruction stream (a 32-bit instruction truncated
/// by the end of a section, or an unsupported >32-bit encoding).
pub fn scan_executable(image: &[u8], ranges: &[(usize, usize)]) -> Result<ScanFindings> {
    let mut out = ScanFindings::default();

    for &(start, len) in ranges {
        let end = start.checked_add(len).ok_or_else(|| {
            anyhow::anyhow!("executable range {start:#x} length {len:#x} overflows")
        })?;
        if end > image.len() {
            bail!(
                "executable range {start:#x}..{end:#x} exceeds image length {}",
                image.len()
            );
        }

        let mut i = start;
        while i < end {
            if i + 2 > end {
                bail!("truncated instruction at offset {i:#x} (1 byte before end of section)");
            }
            let halfword = u16::from_le_bytes([image[i], image[i + 1]]);

            // Compressed (16-bit) instruction: low two bits != 0b11.
            if halfword & 0b11 != 0b11 {
                i += 2;
                continue;
            }

            // 32-bit instruction.
            if i + 4 > end {
                bail!("truncated 32-bit instruction at offset {i:#x}");
            }
            let word = u32::from_le_bytes([image[i], image[i + 1], image[i + 2], image[i + 3]]);

            // RV32IMC has no >32-bit instructions; bits[4:0]==0b11111 marks 48-bit+.
            if word & 0b1_1111 == 0b1_1111 {
                bail!("unsupported wide (>=48-bit) instruction at offset {i:#x}");
            }

            decode_system(word, i, &mut out);
            i += 4;
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a 32-bit CSR instruction.
    fn csr_insn(funct3: u32, rd: u32, rs1: u32, csr: u32) -> [u8; 4] {
        let word = (csr << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | OPCODE_SYSTEM;
        word.to_le_bytes()
    }

    const MSTATUS: u32 = 0x300;

    fn writes(bytes: &[u8]) -> Vec<CsrWrite> {
        scan_executable(bytes, &[(0, bytes.len())])
            .unwrap()
            .csr_writes
    }

    fn privs(bytes: &[u8]) -> Vec<PrivInstr> {
        scan_executable(bytes, &[(0, bytes.len())])
            .unwrap()
            .priv_instrs
    }

    #[test]
    fn csrrw_is_always_a_write() {
        let w = writes(&csr_insn(0b001, 0, 1, MSTATUS)); // csrrw x0, mstatus, x1
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].mnemonic, "csrrw");
        assert_eq!(w[0].csr, MSTATUS as u16);
    }

    #[test]
    fn csrrwi_is_always_a_write() {
        let w = writes(&csr_insn(0b101, 0, 0, MSTATUS));
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].mnemonic, "csrrwi");
    }

    #[test]
    fn csrrs_with_rs1_zero_is_a_read() {
        // csrrs x5, mstatus, x0 == csrr x5, mstatus -> pure read
        assert!(writes(&csr_insn(0b010, 5, 0, MSTATUS)).is_empty());
    }

    #[test]
    fn csrrs_with_rs1_nonzero_is_a_write() {
        let w = writes(&csr_insn(0b010, 5, 6, MSTATUS));
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].mnemonic, "csrrs");
    }

    #[test]
    fn csrrci_with_zero_uimm_is_a_read() {
        assert!(writes(&csr_insn(0b111, 0, 0, MSTATUS)).is_empty());
    }

    #[test]
    fn csrrci_with_nonzero_uimm_is_a_write() {
        let w = writes(&csr_insn(0b111, 0, 0x1f, MSTATUS));
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].mnemonic, "csrrci");
    }

    #[test]
    fn privileged_instructions_are_decoded() {
        for (word, kind) in [
            (0x0000_0073u32, PrivKind::Ecall),
            (0x0010_0073, PrivKind::Ebreak),
            (0x1050_0073, PrivKind::Wfi),
            (0x3020_0073, PrivKind::Mret),
            (0x1020_0073, PrivKind::Sret),
            (0x7b20_0073, PrivKind::Dret),
        ] {
            let p = privs(&word.to_le_bytes());
            assert_eq!(p, [PrivInstr { offset: 0, kind }], "{}", kind.mnemonic());
            // None of these are CSR writes.
            assert!(writes(&word.to_le_bytes()).is_empty());
        }
    }

    #[test]
    fn walks_mixed_compressed_and_full_width() {
        // c.nop, then csrrw x0, mstatus, x1, then c.nop. A naive 4-byte window
        // would misalign on the compressed instructions.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0001u16.to_le_bytes()); // c.nop
        buf.extend_from_slice(&csr_insn(0b001, 0, 1, MSTATUS)); // csrrw
        buf.extend_from_slice(&0x0001u16.to_le_bytes()); // c.nop
        let w = writes(&buf);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].offset, 2);
    }

    #[test]
    fn truncated_32bit_instruction_errors() {
        let buf = [0x73u8, 0x00]; // low bits 0b11 -> expects 4 bytes
        assert!(scan_executable(&buf, &[(0, buf.len())]).is_err());
    }
}
