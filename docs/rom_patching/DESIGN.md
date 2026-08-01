# Design / Gap Analysis: Caliptra MCU ROM Patching

> **Note:** This repo is now **Caliptra-only**. §1–7 below are the original gap
> analysis comparing the OpenTitan `rom_patch` overlay tool against Caliptra's
> needs (it justified building a separate tool). That OpenTitan tool has since
> been removed from this repo; it remains in git history (commit `b056f1c`).
> §8 documents the implemented Caliptra packer.

**Question:** Can the standalone OpenTitan `rom-patch` generator be used to
generate patches for Caliptra MCU ROM patching?

**Scope:** Evaluated against **caliptra-ss#1163** (RFC-0001, *MCU ROM Patching
via PMP Trap-and-Patch*, by R. Schilling). Also notes **caliptra-sw#3399** (the
original overlay-in-RAM RFC).

**Bottom line:** The OpenTitan tool does **not** fit the #1163 PMP
trap-and-patch model. Its entire output (instruction-aligned overlay `.S` +
remap linker script) and its core algorithm (extract aligned ROM bytes, merge
patch, generate trampolines) target a *hardware-remap / overlay* mechanism that
#1163 explicitly rejects. For #1163, a largely **new tool** is required; only
ELF-parsing and capstone-disassembly infrastructure is reusable. (The OT tool
*would* be a good base for #3399's overlay-in-RAM model.)

---

## 1. Mechanism mismatch

| | OpenTitan / #3399 (overlay) | #1163 (PMP trap-and-patch) |
|---|---|---|
| Redirect | HW remaps ROM fetch → overlay RAM | PMP `NA4` no-execute → trap → handler |
| Replacement | Patched copy of original instruction bytes | `void patch_fn(trap_frame_t*)` callback |
| Resume | Falls through overlaid bytes | Handler sets `mepc = target + resume_offset×4`, `mret` |
| Auth | none (in OT tool) | Ed25519 over patch payload |
| Artifact | `.S` + linker script (assembled/linked later) | Signed binary patch block → OTP fuse image |
| HW dependency | ROM patch controller (Caliptra SS lacks this) | Existing VeeR EL2 PMP only |

Because #1163 carries replacement *logic* (a callback), not replacement
*bytes over the original*, the OT tool's central work — aligned-data extraction
and merge — has no analogue.

---

## 2. Component-by-component reuse verdict

| OT tool component (this repo) | #1163 need | Verdict |
|---|---|---|
| `loader/rom.rs` — ELF parse + RV32C disasm + **aligned-data extract/merge** | Resolve target/resume from ROM ELF/map; **no** byte merge | ⚠️ ELF/disasm infra reusable; extraction/merge **not** needed |
| `loader/patch_bin.rs` — parse `.a`, pull `.patch.<name>`, **reject relocations** | Take one fully-linked, **relocation-free** replacement ELF; pull exec+rodata | ⚠️ pattern + no-reloc check reusable |
| `patcher/replacement_patch.rs`, `multi_sized.rs` — overlay merge, size selection | — | ❌ delete |
| `patcher/insertion_patch.rs` — trampoline generation | — (redirect is via PMP/`mepc`) | ❌ delete |
| `generator/*` + `templates/*.j2` — emit `.S` + `.ld` | Emit **binary block** + fuse image | ❌ delete |
| `capstone` RV32IMC setup (`loader/rom.rs:84-90`) | Disassemble replacement for **CSR-write scan** | ✅ reuse, repurposed |
| `goblin` ELF parsing patterns | Extract code/rodata from replacement ELF | ✅ reuse |
| Cargo / `build.rs` / clap scaffolding | Same | ✅ reuse |
| — | **Ed25519 signing** | 🆕 missing → add `ed25519-dalek` |
| — | **CSR allowlist scanner** | 🆕 missing |
| — | **Patch-block packer** | 🆕 missing |
| — | **OTP fuse image** | 🆕 missing (see §5) |

Reusable surface ≈ ELF parse + capstone setup + no-reloc check + scaffolding
(~2 files' worth). The substance of the OT tool (`patcher/`, `generator/`) does
not apply.

---

## 3. What a #1163 packer must do

Maps to RFC-0001 *Patch Toolchain* steps 3–4 ("a single automated tool … takes
a patch description … produces a signed fuse image").

1. **Replacement ELF → code blob.** Consume a pre-built, PIC, relocation-free
   ELF. Extract executable + read-only sections into N×4-byte words. Enforce ABI:
   no `.data`/`.bss`/TLS/ctors/runtime init/mutable globals; GOT (if any)
   resolved entirely within the blob. *(reuses goblin + no-reloc check)*
2. **CSR allowlist scan.** Capstone-disassemble **all** executable sections;
   reject semantic CSR writes per RFC §CSR Allowlist:
   - `csrrw`/`csrrwi` → always a write.
   - `csrrs`/`csrrsi`, `csrrc`/`csrrci` → write iff `rs1 != x0` (else pure read).
   ABI v1 allowlists **no** CSR writes. *(reuses capstone setup)*
3. **Validate.** `resume_offset != 0` (else infinite trap loop),
   `code_size != 0`, code ≤ slot capacity, target & resume **4-byte aligned**,
   target within ROM range.
4. **Pack patch block** (little-endian, naturally aligned):

   | Offset | Size | Field |
   |---|---|---|
   | 0x00 | 64 B | Ed25519 signature (over 0x40..end) |
   | 0x40 | 4 B | Header: `0xA5<<24 \| version<<16 \| CRITICAL(bit0)`; bits 15:1 zero |
   | 0x44 | 4 B | Target ROM address (absolute) |
   | 0x48 | 2 B | Resume offset (words from target) |
   | 0x4A | 2 B | Code size (words, 0–65535) |
   | 0x4C | N×4 B | Replacement instructions (RV32IMC, PIC) |

5. **Ed25519 sign** bytes `0x40..end`, prepend the 64-byte signature.
   Pure Ed25519 (RFC 8032); not ph/ctx.
6. **Emit signed block** (binary). **Do not** emit the OTP image from Rust —
   see §5.

### Suggested CLI

```
caliptra-rom-patch \
  --rom-elf rom.elf \              # for target/resume resolution + range check
  --replacement patch.elf \       # pre-built, PIC, relocation-free
  --target 0x00001040 \           # or --target-symbol <name>
  --resume-offset 1 \             # words; must be != 0
  --version 1 --critical \
  --signing-key ed25519.pem \
  --out patch_block.bin
```

---

## 4. Reference sizing (RFC §OTP Partition Requirements)

- Slot 0: 32 B Ed25519 public key.
- Slots 1–N: patch blocks. Reference = 8 slots × 256 B = 2 KB.
- Per slot: 64 B sig + 12 B header → up to **45 words (180 B)** of code.
- Tool must reject code that exceeds the configured slot size.

---

## 5. OTP fuse-image boundary (decision)

**Decision: the Rust tool emits the signed patch *block* (binary). OTP partition
image generation is handed off to caliptra-ss's existing Python tooling**
(`tools/scripts/fuse_ctrl_script/gen_fuse_ctrl_partitions.py`, with
`src/fuse_ctrl/doc/otp_ctrl_mmap`). Rationale: the fuse layout for
`VENDOR_NON_SECRET_PROD_PARTITION` is owned by that tooling/RTL; duplicating it
in Rust invites drift. The Rust tool stays a *block packer + signer*; slot
placement and partition-image emission live in the Python flow.

The byte-level handoff (producer output, slot mapping requirements, ROM
round-trip, and the open questions below) is specified in
[OTP_CONTRACT.md](OTP_CONTRACT.md).

---

## 6. Open questions / inputs needed

- **Block → OTP handoff format.** What exactly does
  `gen_fuse_ctrl_partitions.py` accept for a slot's bytes (raw binary, hex,
  per-slot file)? Defines the Rust tool's output contract.
- **Slot placement & supersession.** Owned by the Python/provisioning flow, or
  by this tool? RFC's "highest-numbered same-target slot wins" is a
  *provisioning* concern, not a packing one — recommend keeping it out of the
  packer.
- **Signing key infra.** Local Ed25519 key file for bring-up vs. Caliptra key
  provisioning / HSM for production. RFC defers key mgmt.
- **ROM range + symbol resolution.** Source of ROM address range for the
  in-range check (ELF, map file, or constant?).
- **Patch ABI / `trap_frame_t`.** Owned by ROM, not the tool, but the tool's
  validation (CSR allowlist, no `mret`, `ret`-only return) must track the ABI
  version in the header word.

---

## 7. Recommendation

- For **#1163**: build a new `caliptra-rom-patch` packer; reuse only the ELF +
  capstone infra from this repo. Do **not** adapt `patcher/`/`generator/`.
- For **#3399** (if pursued): the OpenTitan overlay generator in this repo is a
  strong base — that model *is* essentially OpenTitan's.

---

## 8. Implementation status (#1163 packer)

**Implemented** as the `caliptra-rom-patch` binary + the `caliptra_rom_patch`
library (crate root):

| Module | Responsibility | RFC ref |
|---|---|---|
| `tools/rom_patch/src/elf.rs` | Flatten replacement ELF → contiguous image; enforce ABI (RV32/ELF32/LE/ET_EXEC, relocation-free, no `.data`/`.bss`/TLS/writable, entry at base, overlap/size caps). Also `rom_executable_ranges` for `--rom-elf` | §Patch ABI |
| `tools/rom_patch/src/csr_scan.rs` | **Pure ISA decoder**: exact RV32IMC walk yielding CSR writes + privileged `SYSTEM` instructions (`PrivKind`). Decides nothing | §CSR Allowlist |
| `tools/rom_patch/src/abi.rs` | **`AbiPolicy::for_version`**: per-version allowed-CSR-writes + forbidden-`PrivKind` set; rejects unknown versions | §Patch ABI |
| `tools/rom_patch/src/block.rs` | Pack the 0x00–0x4C block; sign payload (0x40..end) via the signer | §Patch Block Format, §Signature scope |
| `tools/rom_patch/src/signer.rs` | `PatchSigner` trait + in-process `SeedSigner` (raw Ed25519 seed) | §Ed25519 Verification |
| `tools/rom_patch/src/lib.rs` | `RomBounds`, orchestrate extract→decode→apply-policy→validate→sign | §Patch Toolchain |
| `tools/rom_patch/src/bin/caliptra-rom-patch.rs` | CLI | — |

Note: the scanner uses an exact instruction-length walk (no disassembler
dependency) — RVC has no CSR/privileged ops, so every such access is a 32-bit
`SYSTEM` instruction; the walk is deterministic and avoids the false positives of
a naive 4-byte scan. **Decode vs policy are separated**: `csr_scan` reports ISA
facts; `abi::AbiPolicy` (keyed to the header version) decides what's allowed, so
a kind like `ecall` can be recognised yet permitted. ABI v1 forbids
`mret`/`sret`/`dret`/`wfi`/`ebreak` and allows no CSR writes; unknown versions
are rejected up front.

**Validation** enforced: `resume_offset≠0`, `code_size≠0`, code 4-byte aligned
and ≤ slot capacity, target/resume 4-byte aligned and within the ROM (numeric
range, or an executable ROM section with `--rom-elf`), resume non-overflowing,
≤65535 words.

**Tested:** 45 unit tests (CSR classification incl. read/write boundary,
privileged-instruction decode, ABI-policy per-version incl. unknown-version
rejection, every ELF/ABI rejection path via an in-code ELF32 builder, block
layout, sign+verify round-trip, ROM-bounds checks) + an e2e (`tools/rom_patch/e2e/run.sh`):
real RV32 replacement → target validated against a ROM ELF → pack+sign →
byte-checked block → **independent OpenSSL Ed25519 verify** → CSR-write and
out-of-ROM-target rejections.

**Out of scope (by decision §5):** OTP partition image — hand the signed block
to caliptra-ss's `gen_fuse_ctrl_partitions.py`. Open items in §6 remain
(block→OTP handoff format, slot/supersession ownership, production key infra).

*Status: #1163 packer implemented up to the signed block. This repo is now
Caliptra-only; the OpenTitan overlay generator that the §1–7 comparison refers
to has been removed (it lives in git history at tag/commit `b056f1c`).*

---

## 9. Architecture decisions & residual gaps

The core architecture (single-shot per-block packer; `elf`/`csr_scan`/`block`/
`signer` modules behind an orchestrator; OTP image emission delegated to Python)
is intentional and right-sized. The following are conscious decisions/limits.

### 9.1 Position-independence is only partially verifiable (build contract)

ROM copies each blob to a **runtime-chosen** SRAM address, so the replacement
must be genuinely position-independent. The tool verifies the blob is
**relocation-free**, which is *necessary but not sufficient*: a fully linked
`ET_EXEC` can bake absolute addresses into immediates with no relocation (e.g.
RV32 `-mcmodel=medlow` `lui/addi`), which breaks when relocated.

**Decision:** rely on a build contract rather than attempt (noisy, unreliable)
absolute-address detection. Patches **must** be built `-mcmodel=medany`
(PC-relative `auipc`) with no GOT/absolute references. Documented in the README;
the tool's reloc-free + no-GOT (writable-section) checks catch the common
failure modes. A future enhancement could heuristically flag `lui`-materialized
absolute addresses, accepted as out of scope for now.

### 9.2 Block format implies entry-at-offset-0 / code-first (ABI convention)

The block carries no entry-offset field, so ROM enters the copied blob at its
start. The tool therefore requires `e_entry == image base` and a non-empty
executable section at offset 0 (rodata must follow code by VMA). This couples
the ABI to a linker-script convention (`ENTRY(patch_fn)`, code first). If a
future ABI needs a distinct entry or rodata-first layout, **add an
`entry_offset` field to the block** (an RFC-format change). For now the
convention is enforced and documented.

### 9.3 Set-level handling — `--manifest` mode (implemented)

The per-block packer stays stateless; a `--manifest <hjson>` mode composes a
patch *set* (`tools/rom_patch/src/manifest.rs`): it packs each patch, assigns OTP item slots
(explicit `slot` or auto-sequential), **validates** the set (item-range overlap
is a hard error; capacity vs `num_items`), **reports** same-target supersession
(higher slot wins — intentional, not an error), and emits one combined
`--add-cfg` via `emit_add_cfg_multi`. Ordering is expressed *only* by slot index;
the block format carries no slot field. ROM still resolves the actual
supersession + PMP priority at boot.

Still out of scope (genuinely ROM/provisioning concerns, not pack-time): the
≤64 PMP-entry budget and whether ROM (vs the tool) enforces "no two active
patches on overlapping targets". The tool flags same-target supersession but a
4-byte target is atomic, so distinct targets can't partially overlap.

### 9.4 Static-scan completeness (residual author/build trust)

The CSR/forbidden-instruction scan is necessary-not-sufficient for full ABI
conformance: a `jr`/`jalr` to an absolute ROM address (branch back into ROM) or
other control-flow escapes cannot be caught statically. ABI v1 forbids
`mret`/`sret`/`dret`/`wfi`/`ebreak` and all CSR writes (the forbidden/allowed
sets live in `abi.rs`, keyed to the header version, so an RFC change is a
one-line policy edit). `ecall` is decoded but left permitted in v1 — it traps
cleanly into the handler rather than subverting the trap/return contract.
"Return only via `ret`" otherwise rests on author/build discipline.
