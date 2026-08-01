# Integration Plan — wiring `caliptra-rom-patch` into Caliptra

How the packer connects to the two Caliptra repos. Findings are from a
read-only investigation of `chipsalliance/caliptra-ss` and
`chipsalliance/caliptra-mcu-sw` (commit-current at time of writing). See
[OTP_CONTRACT.md](OTP_CONTRACT.md) for the byte-level handoff and
[DESIGN.md](DESIGN.md) for the tool's design.

> **Status.** The packer itself now lives in this repo at
> [`tools/rom_patch`](../../tools/rom_patch), built and tested by
> [`.github/workflows/rom-patch.yml`](../../.github/workflows/rom-patch.yml).
> It sits next to `tools/scripts/fuse_ctrl_script`, the consumer of its
> `--emit-fuse-cfg` output, so producer and OTP encoding stay in one repo and
> one PR. Workstreams **A** and **C** below are still open; **B** is now
> "surface the in-tree packer from caliptra-mcu-sw's build", not "vendor the
> crate there".

## Picture

```
                 caliptra-mcu-sw                              caliptra-ss (this repo)

   patch_fn.{c,rs} ──build──► replacement.elf ──────► tools/rom_patch (caliptra-rom-patch)
                                                             │
                                       patch_block.bin ◄─────┤
                                                             └─► add-cfg.hjson
                              xtask rom-patch                          │  (--emit-fuse-cfg)
                              (invokes the in-tree packer)             ▼
                                                       gen_fuse_ctrl_vmem.py --add-cfg
                                                                       │
                              MCU ROM (trap-and-patch) ◄── DAI read ─── OTP partition (VENDOR_NON_SECRET_PROD)
                                       ▲                                (size set via gen_fuse_ctrl_partitions.yml)
                                       └── Ed25519 verify, copy to SRAM, set PMP, dispatch patch_fn
```

Three workstreams, increasing effort: **(A) OTP partition** (caliptra-ss, config),
**(B) packer wiring** (caliptra-mcu-sw, small), **(C) ROM consumer**
(caliptra-mcu-sw, greenfield, partly asm).

---

## A. caliptra-ss — size the OTP patch store

The patch store lives in `VENDOR_NON_SECRET_PROD_PARTITION`. Today it is 16 × 32 B
= 512 B; total OTP is 4096 B. It is **configurable**, not RTL-fixed.

Change-set (see OTP_CONTRACT §2a for citations):

1. `tools/scripts/fuse_ctrl_script/gen_fuse_ctrl_partitions.yml`: raise
   `num_vendor_non_secret_fuses` to the slot count needed (e.g. 64 → 2 KB at
   32 B items). Optionally edit the item `size: "32"` → `"256"` in
   `src/fuse_ctrl/templates/otp_ctrl_mmap.hjson.tpl` for 256 B slots.
2. **Bump `otp.depth`** in that template (the one manual step; depth is not
   derived and the generator hard-errors on overflow).
3. Regenerate + commit: `gen_fuse_ctrl_partitions.py -f .../gen_fuse_ctrl_partitions.yml`
   (RTL pkg/reg/RDL, `fuse_ctrl_mmap.{h,c}`, docs) then `gen_fuse_ctrl_vmem.py …`
   (new `otp-img.<depth>.vmem`; update `$readmemh` refs to the old filename).

Caveat: locking is **whole-partition** (one SW digest, one CSR read-lock). Keep
the partition **unlocked** to allow burning later patch slots; rely on Ed25519
for integrity, not the partition digest.

**Decision needed:** final slot count + item size (drives the OTP budget).

---

## B. caliptra-mcu-sw — wire the packer into the build

The repo is a Cargo workspace driven by `xtask`; host tools are surfaced as
xtask subcommands (cf. `xtask` `auth_manifest`, `firmware-bundler`).

The packer is **not** vendored here — it lives in caliptra-ss at
`tools/rom_patch`, which caliptra-mcu-sw already checks out as part of the
subsystem. Surface it rather than copy it:

1. Add a thin `cargo xtask rom-patch` subcommand (`xtask/src/rom_patch.rs`,
   wired in `xtask/src/main.rs`) that builds and invokes the packer out of
   `$CALIPTRA_SS_ROOT/tools/rom_patch` (`cargo run --manifest-path …`). Do not
   add it as a workspace member — it is a standalone crate with its own
   lockfile, and duplicating it would fork the OTP encoding away from the
   partition definition it targets.
2. OTP imaging handoff stays with the existing fuse tooling under
   `provisioning/fuses/` (and the caliptra-ss generator); feed it the
   `--emit-fuse-cfg` output.

**Building a patch replacement** to satisfy the ABI (match repo conventions):
- target `riscv32imc-unknown-none-elf`, `relocation-model=static`,
  `panic=abort`, rust-lld (all already the repo default in `.cargo/config.toml`);
- **add `-Cllvm-args=...`/`-Cmcmodel=medany`** (the repo currently builds medlow;
  PIC needs medany — see DESIGN §9.1);
- a linker script placing `patch_fn` at the image base (template:
  `tests/hello/link.ld`), single flat `.text`, no relocations;
- avoid `-icf=all` folding `patch_fn`.

Developer / CI workflow:
```
write patch_fn  →  build replacement.elf (above flags)
  →  cargo xtask rom-patch --replacement replacement.elf --rom-elf <mcu-rom.elf> \
         --target <addr> --resume-addr <addr> --signing-key <key> \
         --out patch.bin --emit-fuse-cfg add-cfg.hjson
  →  gen_fuse_ctrl_vmem.py --add-cfg add-cfg.hjson …  →  otp-img.vmem
  →  emulator: cargo xtask runtime / test  (ROM reads slot, verifies, applies)
```

**Decisions needed:** whether the xtask also builds the replacement crate; key
source (local seed vs HSM via a `PatchSigner` impl).

---

## C. caliptra-mcu-sw — the ROM trap-and-patch consumer (greenfield)

None of this exists yet (PMP is used only in the runtime kernel; the ROM
`exception_handler` only logs and aborts). Net-new work in crate
`caliptra-mcu-rom-common` (`rom/`) + per-platform `start.s`:

1. **PMP setup at ROM init** — mark each patched 4-byte ROM region `NA4`,
   `L=1, X=0`, at low PMP indices. Use the `rv32i::pmp` CSR helpers already
   in-tree (via `runtime/kernel/veer/src/pmp.rs`). New module called from the
   cold-boot path.
2. **OTP read + verify** — read patch slots via `romtime::Otp` /
   `otp_provision::fuse_read_dai`; parse header pre-verify, bound by `code_size`,
   **Ed25519-verify** over `[0x40, 0x4C+4·code_size)` with the slot-0 key.
   *(Confirm whether `caliptra-drivers`/`caliptra-api` already expose Ed25519
   verify before adding a path.)* Copy verified code to SRAM, `fence.i`,
   populate the dispatch table.
3. **Trap dispatch** — extend the per-platform `start.s` shim (currently saves
   only `sp`→`mscratch`) to build a full `trap_frame_t`; extend
   `exception_handler` (`rom/src/lib.rs`) to: on instruction-access fault with
   `mepc` in the dispatch table, set `mepc = target + resume_offset·4`, call
   `patch_fn(frame)`, restore, `mret`. Today the handler is `-> !` (never
   returns) — the resume path is new.
4. **Supersession + status** — highest-numbered non-empty slot per target wins;
   write `PATCH_STATUS`; record the DPE supplemental measurement (RFC §DICE).

Blockers/unknowns to resolve here: full-trap-frame ABI in asm; M-mode ePMP
semantics for a single no-execute 4-byte fetch-fault region before ePMP lock;
Ed25519-in-ROM availability; exact OTP patch-partition offsets (from A).

---

## Suggested sequencing

0. **Packer in-tree** (`tools/rom_patch` + CI) — **done**.
1. **A** (OTP size) — small, unblocks everything; decide slot count/size.
2. **B** (xtask shim in caliptra-mcu-sw) — small; makes patches producible from
   the firmware build.
3. **C** (ROM consumer) — the bulk; land behind a feature flag, prove on the
   emulator end-to-end (produce → image → boot → verify → apply → resume).

The packer is contract-complete up to the signed block + fuse cfg; A/B/C are the
remaining work.
