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

//! Patch signing abstraction (RFC-0001 §Ed25519 Verification).
//!
//! The packer signs through a [`PatchSigner`] so the in-process raw-seed signer
//! used for bring-up can be swapped for a production backend (HSM, Caliptra key
//! provisioning) without touching the block-packing logic.

use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer as _, SigningKey};

/// Signs a patch payload with pure Ed25519 (RFC 8032).
pub trait PatchSigner {
    /// Returns the 64-byte Ed25519 signature over `payload`.
    fn sign(&self, payload: &[u8]) -> Result<[u8; 64]>;

    /// Returns the 32-byte Ed25519 public key (for OTP slot 0 provisioning).
    fn public_key(&self) -> Result<[u8; 32]>;
}

/// A [`PatchSigner`] backed by a raw 32-byte Ed25519 seed held in process.
///
/// Intended for bring-up and tests. Production signing should provide an
/// alternate [`PatchSigner`] (e.g. an HSM) — the packer only depends on the
/// trait.
pub struct SeedSigner {
    key: SigningKey,
}

impl SeedSigner {
    /// Builds a signer from a raw 32-byte Ed25519 seed.
    pub fn from_seed_bytes(bytes: &[u8]) -> Result<Self> {
        let seed: [u8; 32] = bytes.try_into().map_err(|_| {
            anyhow!(
                "signing key must be a raw 32-byte Ed25519 seed, got {} bytes",
                bytes.len()
            )
        })?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }
}

impl PatchSigner for SeedSigner {
    fn sign(&self, payload: &[u8]) -> Result<[u8; 64]> {
        Ok(self.key.sign(payload).to_bytes())
    }

    fn public_key(&self) -> Result<[u8; 32]> {
        Ok(self.key.verifying_key().to_bytes())
    }
}
