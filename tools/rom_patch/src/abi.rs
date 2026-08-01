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

//! Patch ABI policy, keyed by format version (RFC-0001 §Patch ABI).
//!
//! The header's version field (bits 23:16) selects an [`AbiPolicy`] that decides
//! what the ISA facts from [`crate::csr_scan`] mean: which CSR writes are
//! allowed and which privileged `SYSTEM` instructions are forbidden. Keeping the
//! policy here (rather than hard-coded in the scanner or the orchestrator) means
//! the spec-defined rules live in one place and new ABI versions are a single
//! table entry — and unknown versions are rejected up front.

use anyhow::{bail, Result};

use crate::csr_scan::PrivKind;

/// The allowed/forbidden policy for one patch ABI version.
pub struct AbiPolicy {
    /// The ABI version this policy describes.
    pub version: u8,
    /// CSR numbers whose semantic writes are permitted. Empty = none.
    allowed_csr_writes: &'static [u16],
    /// Privileged `SYSTEM` instructions forbidden in replacement code.
    forbidden: &'static [PrivKind],
}

/// ABI v1: no CSR writes; forbid trap-altering returns, `wfi` (deadlock risk
/// with `MIE` clear), and `ebreak` (debug artifact). `ecall` is recognised by
/// the decoder but not forbidden here — it traps cleanly into the handler rather
/// than subverting the trap/return contract.
const V1_FORBIDDEN: &[PrivKind] = &[
    PrivKind::Ebreak,
    PrivKind::Wfi,
    PrivKind::Mret,
    PrivKind::Sret,
    PrivKind::Dret,
];

impl AbiPolicy {
    /// Returns the policy for a supported `version`, or an error for unknown
    /// versions (RFC-0001: "ROM supports only known versions").
    pub fn for_version(version: u8) -> Result<Self> {
        match version {
            1 => Ok(Self {
                version,
                allowed_csr_writes: &[],
                forbidden: V1_FORBIDDEN,
            }),
            other => bail!("unsupported patch ABI version {other} (supported: 1)"),
        }
    }

    /// Whether a semantic write to `csr` is permitted.
    pub fn csr_write_allowed(&self, csr: u16) -> bool {
        self.allowed_csr_writes.contains(&csr)
    }

    /// Whether `kind` is forbidden in replacement code.
    pub fn is_forbidden(&self, kind: PrivKind) -> bool {
        self.forbidden.contains(&kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_forbids_ebreak_and_returns_but_not_ecall() {
        let p = AbiPolicy::for_version(1).unwrap();
        assert!(p.is_forbidden(PrivKind::Ebreak));
        assert!(p.is_forbidden(PrivKind::Mret));
        assert!(p.is_forbidden(PrivKind::Wfi));
        assert!(!p.is_forbidden(PrivKind::Ecall));
    }

    #[test]
    fn v1_allows_no_csr_writes() {
        let p = AbiPolicy::for_version(1).unwrap();
        assert!(!p.csr_write_allowed(0x300));
    }

    #[test]
    fn unknown_version_is_rejected() {
        assert!(AbiPolicy::for_version(2).is_err());
        assert!(AbiPolicy::for_version(0).is_err());
    }
}
