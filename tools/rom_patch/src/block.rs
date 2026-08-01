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

//! Patch block packing and Ed25519 signing (RFC-0001 §Patch Block Format).
//!
//! Little-endian, naturally aligned:
//!
//! | Offset | Size  | Field                                            |
//! |--------|-------|--------------------------------------------------|
//! | 0x00   | 64 B  | Ed25519 signature (over bytes 0x40 .. end)       |
//! | 0x40   | 4 B   | Header word: magic / version / flags             |
//! | 0x44   | 4 B   | Target ROM address (absolute)                    |
//! | 0x48   | 2 B   | Resume offset (4-byte words from target)         |
//! | 0x4A   | 2 B   | Code size (4-byte words, 0-65535)                |
//! | 0x4C   | N×4 B | Replacement instructions (RV32IMC, PIC)          |
//!
//! Header word bit layout: `31:24` magic (`0xA5`), `23:16` format version,
//! `15:1` reserved (zero), `0` `CRITICAL`.

use anyhow::{bail, ensure, Result};

use crate::signer::PatchSigner;

/// Header magic byte (bits 31:24).
pub const MAGIC: u8 = 0xA5;
/// Ed25519 signature size, prefixed at offset 0x00.
pub const SIGNATURE_SIZE: usize = 64;
/// Offset of the signed payload (header word) within the block.
pub const PAYLOAD_OFFSET: usize = 0x40;
/// Offset of the replacement code within the block.
pub const CODE_OFFSET: usize = 0x4C;

/// Parameters for one patch block.
#[derive(Debug, Clone)]
pub struct BlockParams {
    /// Patch format version (header bits 23:16).
    pub version: u8,
    /// `CRITICAL` flag (header bit 0): failures fail closed when set.
    pub critical: bool,
    /// Absolute target ROM address (must be 4-byte aligned).
    pub target: u32,
    /// Resume offset in 4-byte words from `target` (must be non-zero).
    pub resume_offset: u16,
    /// Replacement code image (length must be a non-zero multiple of 4).
    pub code: Vec<u8>,
}

/// Encodes the 32-bit header word.
pub fn encode_header(version: u8, critical: bool) -> u32 {
    ((MAGIC as u32) << 24) | ((version as u32) << 16) | (critical as u32)
}

impl BlockParams {
    /// Validates the parameters against RFC-0001 invariants.
    ///
    /// `max_code_bytes` bounds the replacement code to the configured OTP slot
    /// capacity (slot size minus the 76-byte signature+header prefix). `None`
    /// disables the slot-capacity check.
    pub fn validate(&self, max_code_bytes: Option<usize>) -> Result<()> {
        ensure!(
            self.target % 4 == 0,
            "target address {:#x} is not 4-byte aligned",
            self.target
        );
        // resume = target + resume_offset*4 is then implicitly 4-byte aligned.
        ensure!(
            self.resume_offset != 0,
            "resume_offset must be non-zero (would be an infinite trap loop)"
        );
        self.target
            .checked_add(u32::from(self.resume_offset) * 4)
            .ok_or_else(|| anyhow::anyhow!("resume address overflows u32"))?;
        ensure!(
            !self.code.is_empty(),
            "code_size must be non-zero (no replacement code)"
        );
        ensure!(
            self.code.len() % 4 == 0,
            "code length {} is not a multiple of 4 bytes",
            self.code.len()
        );

        let words = self.code.len() / 4;
        ensure!(
            words <= u16::MAX as usize,
            "code is {words} words, exceeds the 65535-word field"
        );

        if let Some(max) = max_code_bytes {
            ensure!(
                self.code.len() <= max,
                "code is {} bytes but the slot allows at most {} bytes of code",
                self.code.len(),
                max
            );
        }
        Ok(())
    }

    /// Number of 4-byte code words.
    pub fn code_words(&self) -> u16 {
        (self.code.len() / 4) as u16
    }
}

/// Builds the signed patch block: `signature || payload`.
///
/// The Ed25519 signature covers the payload (`header .. end`), per RFC-0001
/// §Signature scope. Pure Ed25519 (RFC 8032); deterministic, no RNG.
pub fn pack_and_sign(
    params: &BlockParams,
    signer: &dyn PatchSigner,
    max_code_bytes: Option<usize>,
) -> Result<Vec<u8>> {
    params.validate(max_code_bytes)?;

    let mut payload = Vec::with_capacity(12 + params.code.len());
    payload.extend_from_slice(&encode_header(params.version, params.critical).to_le_bytes());
    payload.extend_from_slice(&params.target.to_le_bytes());
    payload.extend_from_slice(&params.resume_offset.to_le_bytes());
    payload.extend_from_slice(&params.code_words().to_le_bytes());
    payload.extend_from_slice(&params.code);

    let signature = signer.sign(&payload)?;

    let mut block = Vec::with_capacity(SIGNATURE_SIZE + payload.len());
    block.extend_from_slice(&signature);
    block.extend_from_slice(&payload);

    // Sanity: layout offsets are exactly as specified.
    debug_assert_eq!(block.len(), CODE_OFFSET + params.code.len());
    if block.len() != CODE_OFFSET + params.code.len() {
        bail!("internal error: block layout mismatch");
    }
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{PatchSigner, SeedSigner};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn test_key() -> SeedSigner {
        // Fixed seed -> deterministic signatures, no RNG needed.
        SeedSigner::from_seed_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    fn header_encoding() {
        assert_eq!(encode_header(1, false), 0xA501_0000);
        assert_eq!(encode_header(1, true), 0xA501_0001);
        assert_eq!(encode_header(0xFF, true), 0xA5FF_0001);
        // Only magic, version, and bit 0 are ever set; bits 15:1 stay zero.
        assert_eq!(encode_header(2, false) & 0x0000_FFFE, 0);
    }

    fn sample(code_words: usize) -> BlockParams {
        BlockParams {
            version: 1,
            critical: false,
            target: 0x0000_1040,
            resume_offset: 1,
            code: [0x13, 0x00, 0x00, 0x00].repeat(code_words), // `nop` words
        }
    }

    #[test]
    fn layout_and_fields() {
        let p = sample(3);
        let block = pack_and_sign(&p, &test_key(), None).unwrap();

        assert_eq!(block.len(), CODE_OFFSET + 12); // 76 + 3*4
                                                   // Signature occupies [0, 64). Header at 0x40.
        let header = u32::from_le_bytes(block[0x40..0x44].try_into().unwrap());
        assert_eq!(header, 0xA501_0000);
        // Target at 0x44.
        assert_eq!(
            u32::from_le_bytes(block[0x44..0x48].try_into().unwrap()),
            0x0000_1040
        );
        // Resume offset at 0x48.
        assert_eq!(u16::from_le_bytes(block[0x48..0x4A].try_into().unwrap()), 1);
        // Code size (words) at 0x4A.
        assert_eq!(u16::from_le_bytes(block[0x4A..0x4C].try_into().unwrap()), 3);
    }

    #[test]
    fn signature_verifies_over_payload() {
        let p = sample(2);
        let key = test_key();
        let block = pack_and_sign(&p, &key, None).unwrap();

        let vk = VerifyingKey::from_bytes(&key.public_key().unwrap()).unwrap();
        let sig = Signature::from_bytes(block[..64].try_into().unwrap());
        // Verifies over exactly bytes 0x40..end.
        assert!(vk.verify_strict(&block[PAYLOAD_OFFSET..], &sig).is_ok());
        // Tampering with the payload breaks verification.
        let mut tampered = block.clone();
        tampered[CODE_OFFSET] ^= 0xFF;
        let sig2 = Signature::from_bytes(tampered[..64].try_into().unwrap());
        assert!(vk.verify(&tampered[PAYLOAD_OFFSET..], &sig2).is_err());
    }

    #[test]
    fn rejects_resume_offset_zero() {
        let mut p = sample(1);
        p.resume_offset = 0;
        assert!(pack_and_sign(&p, &test_key(), None).is_err());
    }

    #[test]
    fn rejects_empty_code() {
        let mut p = sample(1);
        p.code.clear();
        assert!(pack_and_sign(&p, &test_key(), None).is_err());
    }

    #[test]
    fn rejects_unaligned_code() {
        let mut p = sample(1);
        p.code.push(0x00); // now 5 bytes
        assert!(pack_and_sign(&p, &test_key(), None).is_err());
    }

    #[test]
    fn rejects_unaligned_target() {
        let mut p = sample(1);
        p.target = 0x1042;
        assert!(pack_and_sign(&p, &test_key(), None).is_err());
    }

    #[test]
    fn rejects_resume_address_overflow() {
        let mut p = sample(1);
        p.target = 0xffff_fffc;
        p.resume_offset = 1;
        assert!(pack_and_sign(&p, &test_key(), None).is_err());
    }

    #[test]
    fn rejects_code_exceeding_slot() {
        let p = sample(2); // 8 bytes of code
                           // Slot allows at most 4 bytes of code.
        assert!(pack_and_sign(&p, &test_key(), Some(4)).is_err());
        assert!(pack_and_sign(&p, &test_key(), Some(8)).is_ok());
    }
}
