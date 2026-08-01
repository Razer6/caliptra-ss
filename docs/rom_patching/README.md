# MCU ROM Patching

Specification and design notes for **MCU ROM patching via PMP trap-and-patch**
(RFC-0001, [caliptra-ss#1163]). The host-side packer that produces signed patch
blocks lives in [`tools/rom_patch`](../../tools/rom_patch).

| Document | What it covers |
|----------|----------------|
| [rfc-0001-mcu-rom-patching.md](rfc-0001-mcu-rom-patching.md) | The RFC: threat model, patch block format, patch ABI, ROM boot flow, DICE measurement |
| [OTP_CONTRACT.md](OTP_CONTRACT.md) | Byte-level handoff between the packer, `gen_fuse_ctrl_vmem.py`, and MCU ROM. Read this before burning fuses |
| [DESIGN.md](DESIGN.md) | Packer design and rationale: module split, ISA scanning, signing, trade-offs |
| [INTEGRATION.md](INTEGRATION.md) | Remaining upstream work: OTP partition sizing here, ROM consumer in caliptra-mcu-sw |

## Flow

```
patch_fn.S ──build──► replacement.elf
                          │
                          ▼
              tools/rom_patch (caliptra-rom-patch)
                          │
        patch_block.bin ──┴──► add-cfg.hjson
                                    │
                                    ▼
    tools/scripts/fuse_ctrl_script/gen_fuse_ctrl_vmem.py --add-cfg
                                    │
                                    ▼
                          otp-img.<depth>.vmem
                                    │
                   VENDOR_NON_SECRET_PROD_PARTITION
                                    │
                                    ▼
     MCU ROM: DAI read ─► Ed25519 verify ─► copy to SRAM ─► PMP ─► dispatch
```

The packer's `--emit-fuse-cfg` output is written against this repo's item
encoding: partition `VENDOR_NON_SECRET_PROD_PARTITION`, item prefix
`CPTRA_SS_VENDOR_SPECIFIC_NON_SECRET_FUSE_`, 32-byte items — see
`src/fuse_ctrl/templates/otp_ctrl_mmap.hjson.tpl`. If that partition's item size
or count changes, update the packer defaults in
`tools/rom_patch/src/fuse_cfg.rs` (and its `default_layout_matches_caliptra_ss`
test) to match.

[caliptra-ss#1163]: https://github.com/chipsalliance/caliptra-ss/pull/1163
