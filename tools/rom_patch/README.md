# caliptra-rom-patch

Packer for **Caliptra MCU ROM patches** (RFC-0001, [caliptra-ss#1163] —
*MCU ROM Patching via PMP Trap-and-Patch*).

Given a pre-built replacement function, it produces a signed binary **patch
block**: it flattens the replacement ELF, enforces the patch ABI, scans for
disallowed CSR writes, packs the RFC-0001 block, and Ed25519-signs the payload.

OTP partition image generation is **out of scope** — hand the signed block to
this repo's fuse tooling in [tools/scripts/fuse_ctrl_script]. The byte-level
handoff (slot mapping, the "verbatim LE, zero-padded" invariant, and open items)
is in [OTP_CONTRACT.md]. See [DESIGN.md] for rationale and
[rfc-0001-mcu-rom-patching.md] for the RFC.

For the remaining upstream work (OTP partition sizing here, packer xtask and
ROM consumer in caliptra-mcu-sw), see [INTEGRATION.md].

[caliptra-ss#1163]: https://github.com/chipsalliance/caliptra-ss/pull/1163
[tools/scripts/fuse_ctrl_script]: ../scripts/fuse_ctrl_script
[OTP_CONTRACT.md]: ../../docs/rom_patching/OTP_CONTRACT.md
[INTEGRATION.md]: ../../docs/rom_patching/INTEGRATION.md
[DESIGN.md]: ../../docs/rom_patching/DESIGN.md
[rfc-0001-mcu-rom-patching.md]: ../../docs/rom_patching/rfc-0001-mcu-rom-patching.md

## What it does

```
replacement.elf ──► flatten + ABI enforce ──► CSR-write scan ──► pack ──► Ed25519 sign ──► patch_block.bin
                    (reloc-free, no .data/      (csrrw/i always;
                     .bss/TLS, entry at base)    csrrs/c[i] if rs1≠0)
```

Block layout (RFC-0001 §Patch Block Format), little-endian:

| Offset | Size  | Field |
|--------|-------|-------|
| 0x00   | 64 B  | Ed25519 signature (over 0x40..end) |
| 0x40   | 4 B   | Header: `0xA5<<24 \| version<<16 \| CRITICAL(bit0)` |
| 0x44   | 4 B   | Target ROM address |
| 0x48   | 2 B   | Resume offset (4-byte words from target) |
| 0x4A   | 2 B   | Code size (4-byte words) |
| 0x4C   | N×4 B | Replacement instructions (RV32IMC, PIC) |

## Build

Requires Rust ≥ 1.80. All dependencies are on crates.io (no git deps, no C
toolchain needed to build the packer itself). This crate is standalone — it is
deliberately *not* part of any workspace, so building it does not require a
Rust toolchain for the rest of the repo.

```sh
cd $CALIPTRA_SS_ROOT/tools/rom_patch
cargo build --release      # -> target/release/caliptra-rom-patch
```

## Run

```sh
caliptra-rom-patch \
  --replacement patch_fn.elf \   # pre-built, PIC, relocation-free; patch_fn at base
  --target 0x1040 \              # ROM address to patch (4-byte aligned)
  --resume-addr 0x1044 \         # or --resume-offset 1 (words); must be non-zero
  --version 1 \                  # patch ABI version; --critical to fail closed
  --signing-key key.bin \        # raw 32-byte Ed25519 seed
  --slot-size 256 \              # OTP slot bytes; code bounded to slot-0x4C
  --rom-elf rom.elf \            # validate target/resume fall in ROM code (preferred)
  --out patch_block.bin \
  --pubkey-out pub.bin           # optional 32-byte pubkey for OTP slot 0
```

Target validation, in order of strength:
- **`--rom-elf <path>`** — target *and* resume must fall inside an executable
  (`SHF_EXECINSTR`) section of the ROM ELF. Preferred.
- **`--rom-base <a> --rom-size <n>`** — numeric `[a, a+n)` window only.
- neither — skipped (logged as a warning).

`--target` / `--resume-addr` / `--rom-*` accept `0x`-hex or decimal. Logging via
`RUST_LOG` (default `info`).

### Building a replacement

The replacement is a single function `void patch_fn(trap_frame_t *frame)`, built
position-independent and relocation-free, with `patch_fn` at the image base:

```sh
riscv64-elf-gcc -march=rv32imc_zicsr -mabi=ilp32 -mcmodel=medany \
  -nostdlib -nostartfiles -Wl,-T,patch.ld -o patch_fn.elf patch_fn.S
```
with `patch.ld`:
```ld
ENTRY(patch_fn)
SECTIONS { . = 0; .text : { *(.text*) *(.rodata*) } /DISCARD/ : { *(.comment) *(.note*) } }
```

The patch ABI (RFC-0001 §Patch ABI): no `.data`/`.bss`/TLS/mutable globals, no
semantic CSR writes (ABI v1), return with `ret` (never `mret`).

> **Position-independence is load-bearing** — ROM copies the blob to a runtime
> SRAM address. Build with `-mcmodel=medany` (PC-relative `auipc`) and avoid
> GOT/absolute address references. The tool verifies the blob is
> *relocation-free*, which is necessary but **not sufficient** for PIC: a fully
> linked binary can still bake in absolute addresses with no relocation. Use the
> right codegen flags. See [DESIGN.md] §9.

## Patch sets (manifest)

To pack multiple patches into one OTP partition image, use an hjson manifest and
emit a single combined `--add-cfg`:

```sh
caliptra-rom-patch --manifest patches.hjson --out add-cfg.hjson
```
```hjson
{
  signing_key: "ed25519_seed.bin"   // raw 32-byte seed
  rom_elf: "mcu-rom.elf"            // optional; validates every target/resume
  item_size: 32                     // OTP item size (bytes)
  num_items: 16                     // optional capacity check
  patches: [
    { replacement: "pll_fix.elf",  target: "0x1040", resume_offset: 1 }   // auto slot
    { replacement: "gpio_fix.elf", target: "0x2000", resume_addr: "0x2008", slot: 8 }
  ]
}
```

Slots are auto-assigned sequentially unless `slot` is given. The tool **rejects**
overlapping OTP item ranges and over-capacity sets, and **reports** same-target
supersession (the higher slot wins at ROM boot — that's how a field update
replaces an earlier patch, since OTP is append-only). Order matters only between
patches on the *same* target; distinct targets are independent.

## Test

```sh
cargo test        # unit tests (CSR classification, block layout, sign/verify, validation)
cargo build && ./e2e/run.sh   # round-trip: pack+sign, add-cfg reconstruct, OpenSSL verify
```
`e2e/run.sh` needs a bare-metal RISC-V GCC, `python3`, and `openssl`. It picks
the first of `riscv64-elf-gcc` / `riscv64-unknown-elf-gcc` /
`riscv32-unknown-elf-gcc` on `PATH` (override with `RISCV_CC`) and probes for an
`-march` string that assembles `csrr`. All artifacts land in `target/e2e`
(override with `E2E_OUT`) — nothing is written into the source tree. Both
`cargo test` and the e2e run in CI, see
[.github/workflows/rom-patch.yml](../../.github/workflows/rom-patch.yml).

## License

Apache-2.0 — see the repository-root [LICENSE](../../LICENSE).
