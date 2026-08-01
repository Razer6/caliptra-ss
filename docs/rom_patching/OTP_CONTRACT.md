# OTP Contract — packer → fuse image → MCU ROM

This document pins the integration seam between `caliptra-rom-patch` (the packer)
and the OTP fuse partition that MCU ROM reads at boot. It is the highest-risk
boundary in the system: a byte-order, padding, or length mismatch produces a
block that **fails signature verification on the device**, after the fuses are
burned (irreversible). Get this contract right before provisioning.

Three parties:

1. **Packer** — `caliptra-rom-patch` (this repo). Output fully defined in §1.
2. **Fuse-image generator** — caliptra-ss `tools/scripts/fuse_ctrl_script/
   gen_fuse_ctrl_partitions.py`. Requirements in §2; exact mapping **TBC** (§5).
3. **MCU ROM reader** — RFC-0001 (caliptra-ss#1163). Round-trip in §3.

---

## 1. Producer output (defined by this tool)

`--out` writes exactly one little-endian patch block:

| Offset | Size  | Field |
|--------|-------|-------|
| 0x00   | 64 B  | Ed25519 signature over `[0x40 .. end)` |
| 0x40   | 4 B   | Header: `0xA5<<24 \| version<<16 \| CRITICAL(bit0)`; bits 15:1 = 0 |
| 0x44   | 4 B   | Target ROM address (absolute) |
| 0x48   | 2 B   | Resume offset (4-byte words from target) |
| 0x4A   | 2 B   | Code size = N (4-byte words) |
| 0x4C   | N×4 B | Replacement instructions (RV32IMC, PIC) |

Guarantees:

- **Length** = `0x4C + 4·N` = `76 + 4·N` bytes; `N ≥ 1` ⇒ min 80 B; always a
  multiple of 4.
- **Signed region** is exactly `[0x40, 0x4C + 4·N)` (12-byte header + code). The
  64-byte signature prefix is *not* self-covered; nothing after the code exists
  in the block.
- **Non-zero marker**: the header high byte is magic `0xA5`, so a populated block
  is never all-zero — this is how an empty (unburned) slot is told apart from a
  real one.
- **Determinism**: Ed25519 (RFC 8032, pure) is deterministic; identical inputs
  produce byte-identical output. Fuse images are reproducible.
- **Public key** (`--pubkey-out`): raw 32 bytes, little-endian per RFC 8032, for
  OTP slot 0.

The packer does **not** emit the partition image, choose a slot, handle
supersession, ECC, or partition locking. That is §2.

---

## 2. Slot mapping the fuse generator MUST honor

Partition: `VENDOR_NON_SECRET_PROD_PARTITION`. Findings below are confirmed
against caliptra-ss (`tools/scripts/fuse_ctrl_script/`,
`src/fuse_ctrl/data/otp_ctrl_mmap.hjson`) — see §6 for citations.

1. **Verbatim bytes.** A slot holds one block copied byte-for-byte from the slot
   base. No reordering, no per-field transform.
2. **Byte order — CONFIRMED little-endian, with one encoding caveat.** The fuse
   pipeline is uniformly LE with **no per-word byte-swap** (`otp_mem_img.py`
   value→bytes→word all LE), and ROM reads it back LE via the DAI
   (`romtime::Otp::read_word`), so `OTP[N] == block[N]`. **Caveat:** the
   generator's `--add-cfg` input gives each item `value` as a hex *string*
   parsed MSB-first but stored LSB-first (`common.py:_parse_hex`). So each item's
   value must be written **byte-reversed**. The packer should emit this directly
   (see §5) rather than leaving it to a human.
3. **Zero-padded tail.** `block_len ≤ slot_size`; the remaining slot bytes stay
   unburned (read as 0). ROM must ignore them (see §3) — they are not signed.
4. **Capacity — CONFIGURABLE, not a blocker.** The partition size is generated
   from `num_vendor_non_secret_fuses` (count of 32 B items) in
   `gen_fuse_ctrl_partitions.yml`; item size is a template constant editable to
   256 B. Extend it to hold the patch store — see §2a.
5. **ECC transparent — CONFIRMED.** ECC is computed per 16-bit OTP word at
   image-gen time and checked/stripped by HW on DAI reads; the data byte stream
   ROM observes is unchanged.
6. **Digest / lock & incremental burn — whole-partition only.** The partition
   uses a *software* digest write-lock and a *single* CSR read-lock covering the
   **entire** partition (no per-slot locking). Incremental burns (OTP 0→1) are
   fine **while the partition digest is unlocked**; once the SW digest is
   computed the partition is write-locked. Integrity for patches rests on the
   Ed25519 signature, **not** the partition digest, so leaving the digest
   unlocked to allow later patch burns is acceptable.

### 2a. Extending the partition (the change-set)

Confirmed mechanics (caliptra-ss):

1. Set the slot count in `tools/scripts/fuse_ctrl_script/gen_fuse_ctrl_partitions.yml`
   (`num_vendor_non_secret_fuses`). Optionally change item `size: "32"` → `"256"`
   in `src/fuse_ctrl/templates/otp_ctrl_mmap.hjson.tpl` for 256 B slots (same
   footprint, fewer items). Partition size must stay 8-byte aligned (256 is fine).
2. **Manually bump `otp.depth`** in the same template (`width:2 × depth` = total
   OTP bytes). This is the **one** manual step — depth is *not* derived from the
   partition sum, and the generator **hard-errors** ("OTP is not big enough") on
   overflow rather than silently growing. Everything else (offsets, digest
   offset, downstream partition shifts, `OtpByteAddrWidth`, RTL
   `OtpDepth`/`OtpAddrWidth`, SW window) is derived from `depth`.
3. Regenerate: `gen_fuse_ctrl_partitions.py -f .../gen_fuse_ctrl_partitions.yml`
   (rewrites `otp_ctrl_part_pkg.sv`, reg pkg/top, RDL, `fuse_ctrl_mmap.{h,c}`,
   docs), then `gen_fuse_ctrl_vmem.py …` (new `otp-img.<depth>.vmem`; update any
   `$readmemh` references to the old filename). Commit all generated artifacts.

This is a config + regen change in caliptra-ss (which propagates to
caliptra-mcu-sw's generated `fuses`), **not** hand-written RTL.

---

## 3. Consumer round-trip (MCU ROM, per RFC-0001)

For the contract to close, ROM must:

1. Treat an all-zero slot as **empty** → skip.
2. Parse the header *before* verification only for magic / version / `CRITICAL` /
   target / `code_size`, and **bound `code_size` to the slot** before copying.
3. Verify Ed25519 with the slot-0 public key over **`[0x40, 0x4C + 4·code_size)`**
   — the signed length is derived from `code_size`, **not** the slot size.
   Trailing pad bytes are outside the signed region by construction.
4. Resolve supersession (highest-numbered non-empty slot per target wins) — a
   provisioning/ROM concern, outside the packer.

---

## 4. The invariant, stated once

> The bytes ROM hashes for verification must be **byte-identical** to the bytes
> this tool signed: `slot[0x40 .. 0x4C + 4·code_size]`. The slot content is the
> block, **verbatim, little-endian, zero-padded**. Any transform in between —
> byte-swap, reorder, truncation, ECC bleed into the logical stream — silently
> breaks verification on a burned device.

---

## 5. Status of the open items (resolved against the repos)

Resolved by investigating caliptra-ss + caliptra-mcu-sw (citations §6):

- ✅ **Input format**: the value-bearing generator is `gen_fuse_ctrl_vmem.py`
  (not `gen_fuse_ctrl_partitions.py`); item contents come via `--add-cfg
  <hjson>`, one hex-string `value` per item. → **Implemented**: the packer's
  `--emit-fuse-cfg` chunks the block into the partition's items and emits that
  hjson with **per-item byte-reversed** hex (§2.2). `tools/rom_patch/src/fuse_cfg.rs`; verified
  by `tools/rom_patch/e2e/run.sh` (reconstructs the block byte-for-byte via the caliptra-ss
  `(value>>8k)&0xff` rule).
- ✅ **Byte order**: uniform LE, no per-word swap; ROM reads LE via DAI (§2.2).
- ✅ **ECC**: transparent to ROM reads (§2.5).
- ✅ **Capacity**: configurable via `num_vendor_non_secret_fuses` + one manual
  `otp.depth` bump (§2a) — not an RTL blocker.
- ⚠️ **Digest/lock**: whole-partition only; leave digest unlocked to allow later
  patch burns; integrity rests on Ed25519, not the digest (§2.6).
- 📋 **Slot assignment + supersession ownership**: recommended provisioning/ROM,
  not the packer (keeps the packer per-block and stateless). Still a design call.

Remaining for production: confirm the exact `--add-cfg` schema field names against
the live tool when wiring `--emit-fuse-cfg`, and decide who owns slot/supersession.

## 6. Where this maps in the repos

- **caliptra-ss** (OTP definition + image): partition in
  `src/fuse_ctrl/data/otp_ctrl_mmap.hjson` / `…/templates/otp_ctrl_mmap.hjson.tpl`
  (count in `tools/scripts/fuse_ctrl_script/gen_fuse_ctrl_partitions.yml`);
  image via `gen_fuse_ctrl_vmem.py --add-cfg`; DAI read map in
  `src/integration/rtl/fuse_ctrl_mmap.h`.
- **caliptra-mcu-sw** (packer + ROM consumer): packer fits as a workspace crate
  surfaced via a `cargo xtask rom-patch` subcommand (mirrors
  `xtask` `auth_manifest`/`firmware-bundler`); OTP imaging lives under
  `provisioning/fuses/`. ROM reads slots via `romtime::Otp` /
  `otp_provision::fuse_read_dai`; the trap-and-patch consumer extends
  `exception_handler` (`rom/src/lib.rs`) + the per-platform `start.s` shim and
  adds PMP NA4 setup at ROM init (PMP primitives already in-tree via the veer
  kernel). This consumer is greenfield.
