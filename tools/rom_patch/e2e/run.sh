#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# End-to-end test for caliptra-rom-patch (RFC-0001 / caliptra-ss#1163).
#
# Builds a relocation-free RV32 replacement (patch_fn at image base), packs +
# signs the patch block, checks the block layout, independently verifies the
# Ed25519 signature with OpenSSL, and confirms a CSR-write replacement is
# rejected.
#
# Requires: a bare-metal RISC-V GCC that can assemble RV32IMC + CSR access,
# python3, openssl, and a built caliptra-rom-patch binary.
#
# Overrides:
#   RISCV_CC                 bare-metal RISC-V compiler. Default: first of
#                            riscv64-elf-gcc / riscv64-unknown-elf-gcc /
#                            riscv32-unknown-elf-gcc found on PATH.
#   CALIPTRA_ROM_PATCH_BIN   path to the packer binary.
#   E2E_OUT                  scratch directory. Default: ../target/e2e.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
# Everything this script produces (ELFs, keys, blocks, hjson) is a build
# artifact and stays out of the source tree: the repo license-header check
# greps every file outside the excluded directories, and `target` is excluded.
OUT="${E2E_OUT:-$SRC/../target/e2e}"
rm -rf "$OUT"
mkdir -p "$OUT"
cd "$OUT"
echo "e2e scratch dir: $OUT"

if [[ -z "${RISCV_CC:-}" ]]; then
    for cc in riscv64-elf-gcc riscv64-unknown-elf-gcc riscv32-unknown-elf-gcc; do
        if command -v "$cc" > /dev/null 2>&1; then
            RISCV_CC="$cc"
            break
        fi
    done
fi
if [[ -z "${RISCV_CC:-}" ]]; then
    echo "error: no bare-metal RISC-V GCC found; set RISCV_CC" >&2
    exit 1
fi
echo "using RISCV_CC=$RISCV_CC"

# patch_fn.S reads a CSR, so the -march string has to admit `csrr`. On GCC >= 12
# that needs an explicit `_zicsr`; on older toolchains `_zicsr` is not a valid
# suffix and CSR access is part of the base ISA. Probe for the one that works
# rather than guessing from the compiler version.
RVARCH=""
for arch in rv32imc_zicsr rv32imc; do
    if echo 'csrr t1, mcycle' \
            | "$RISCV_CC" -march="$arch" -mabi=ilp32 -x assembler -c -o /dev/null - \
              > /dev/null 2>&1; then
        RVARCH="$arch"
        break
    fi
done
if [[ -z "$RVARCH" ]]; then
    echo "error: $RISCV_CC assembles 'csrr' under neither rv32imc_zicsr nor rv32imc" >&2
    exit 1
fi
echo "using -march=$RVARCH"

RVFLAGS=(-march="$RVARCH" -mabi=ilp32 -nostdlib -nostartfiles -Wl,-T,"$SRC/patch.ld")
BIN="${CALIPTRA_ROM_PATCH_BIN:-$SRC/../target/debug/caliptra-rom-patch}"

echo "== build replacements + stand-in ROM =="
"$RISCV_CC" "${RVFLAGS[@]}" -o patch_fn.elf     "$SRC/patch_fn.S"
"$RISCV_CC" "${RVFLAGS[@]}" -o patch_fn_bad.elf "$SRC/patch_fn_bad.S"
"$RISCV_CC" -march="$RVARCH" -mabi=ilp32 -nostdlib -nostartfiles \
  -Wl,-T,"$SRC/rom.ld" -o rom.elf "$SRC/rom.S"

echo "== fixed signing seed =="
python3 -c "open('key.bin','wb').write(bytes(range(32)))"

echo "== pack + sign (positive, target validated against ROM ELF) =="
"$BIN" \
  --replacement patch_fn.elf \
  --target 0x1040 --resume-addr 0x1044 --version 1 \
  --signing-key key.bin --slot-size 256 \
  --rom-elf rom.elf \
  --out patch_block.bin --pubkey-out pub.bin \
  --emit-fuse-cfg add-cfg.hjson --fuse-item-size 32

echo "== fuse add-cfg reconstructs the block (LE per-item round-trip) =="
python3 - <<'PY'
import re
block = open('patch_block.bin','rb').read()
cfg = open('add-cfg.hjson').read()
vals = re.findall(r'value:\s*"0x([0-9a-fA-F]+)"', cfg)
otp = bytearray()
for v in vals:
    n = int(v, 16)
    otp += bytes((n >> (8*k)) & 0xFF for k in range(32))  # caliptra-ss rule, 32B items
assert otp[:len(block)] == block, "fuse cfg does not reconstruct the block"
assert all(b == 0 for b in otp[len(block):]), "non-zero pad"
print("fuse cfg OK: %d items reconstruct the %d-byte block verbatim" % (len(vals), len(block)))
PY

echo "== check block layout =="
python3 - <<'PY'
b = open('patch_block.bin','rb').read()
import struct
assert len(b) == 88, len(b)
header, target, resume, words = struct.unpack('<IIHH', b[0x40:0x4C])
assert header == 0xA5010000, hex(header)   # magic A5, v1, not critical
assert target == 0x1040, hex(target)
assert resume == 1, resume
assert words  == 3, words
assert len(b) == 0x4C + words*4
print("layout OK: header=%#010x target=%#x resume=%d words=%d" % (header,target,resume,words))
PY

echo "== independent Ed25519 verify (OpenSSL) =="
python3 - <<'PY'
import base64
pub = open('pub.bin','rb').read()
der = bytes.fromhex('302a300506032b6570032100') + pub
open('pub.pem','wb').write(b"-----BEGIN PUBLIC KEY-----\n"+base64.encodebytes(der)+b"-----END PUBLIC KEY-----\n")
b = open('patch_block.bin','rb').read()
open('sig.bin','wb').write(b[:64]); open('payload.bin','wb').write(b[64:])
PY
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in payload.bin -sigfile sig.bin

echo "== CSR-write replacement must be rejected (negative) =="
if "$BIN" --replacement patch_fn_bad.elf --target 0x1040 --resume-offset 1 \
      --signing-key key.bin --out should_not_exist.bin 2>neg_csr.txt; then
  echo "FAIL: bad patch was accepted"; exit 1
fi
grep -q "CSR write(s) not allowed" neg_csr.txt || { echo "FAIL: wrong rejection reason"; cat neg_csr.txt; exit 1; }
test ! -e should_not_exist.bin || { echo "FAIL: output written on rejection"; exit 1; }
echo "PASS: CSR write rejected ($(grep -o 'csrrw to CSR[^ ]* [^ ]*' neg_csr.txt | head -1))"

echo "== target outside ROM code must be rejected (negative) =="
if "$BIN" --replacement patch_fn.elf --target 0x40000 --resume-offset 1 \
      --signing-key key.bin --rom-elf rom.elf --out should_not_exist.bin 2>neg_rom.txt; then
  echo "FAIL: out-of-ROM target accepted"; exit 1
fi
grep -q "not within an executable ROM section" neg_rom.txt || { echo "FAIL: wrong reason"; cat neg_rom.txt; exit 1; }
echo "PASS: out-of-ROM target rejected"

echo "== manifest: pack a 2-patch set into one add-cfg =="
cat > patches.hjson <<EOF
{
  // two patches in one OTP partition image, auto-assigned slots
  signing_key: "key.bin"
  rom_elf: "rom.elf"
  item_size: 32
  num_items: 16
  patches: [
    { replacement: "patch_fn.elf", target: "0x1040", resume_offset: 1 }
    { replacement: "patch_fn.elf", target: "0x1050", resume_offset: 1 }
  ]
}
EOF
"$BIN" --manifest patches.hjson --out add-cfg-set.hjson
python3 - <<'PY'
import re
cfg = open('add-cfg-set.hjson').read()
items = re.findall(r'name:\s*"([^"]+)",\s*value:\s*"0x([0-9a-fA-F]+)"', cfg)
assert len(items) == 6, "expected 6 items (3 per 88B block), got %d" % len(items)
otp = bytearray()
for _, v in items:
    n = int(v, 16)
    otp += bytes((n >> (8*k)) & 0xFF for k in range(32))
# block0 at item 0 (byte 0), block1 at item 3 (byte 96); header magic 0xA5 at +0x43
for off in (0, 96):
    assert otp[off + 0x43] == 0xA5, "block header magic missing at %#x" % off
    tgt = int.from_bytes(otp[off+0x44:off+0x48], 'little')
    assert tgt in (0x1040, 0x1050), hex(tgt)
print("manifest OK: 6 items, two signed blocks at items 0 and 3, targets 0x1040/0x1050")
PY

echo "== manifest: overlapping OTP slots must be rejected (negative) =="
cat > bad.hjson <<EOF
{
  signing_key: "key.bin"
  item_size: 32
  patches: [
    { replacement: "patch_fn.elf", target: "0x1040", resume_offset: 1, slot: 0 }
    { replacement: "patch_fn.elf", target: "0x1050", resume_offset: 1, slot: 1 }
  ]
}
EOF
if "$BIN" --manifest bad.hjson --out should_not_exist.hjson 2>neg_slots.txt; then
  echo "FAIL: overlapping slots accepted"; exit 1
fi
grep -q "overlapping OTP items" neg_slots.txt || { echo "FAIL: wrong reason"; cat neg_slots.txt; exit 1; }
echo "PASS: overlapping slots rejected"

echo
echo "ALL CALIPTRA E2E CHECKS PASSED"
