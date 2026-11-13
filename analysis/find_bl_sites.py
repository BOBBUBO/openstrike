#!/usr/bin/env python3
"""Find all BL (branch-link) call sites in .text targeting given addresses."""
import struct
import sys

ELF = 'decompiled/native/lib/arm64-v8a/libGame.so'
data = open(ELF, 'rb').read()
TEXT_START = 0x1DC0420
TEXT_END = 0x5D008B4
targets = {int(x, 0) for x in sys.argv[1:]}

hits = {}
for pc in range(TEXT_START, TEXT_END - 3, 4):
    insn = struct.unpack_from('<I', data, pc)[0]
    if insn & 0xFC000000 != 0x94000000:
        continue
    imm = insn & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    tgt = pc + (imm << 2)
    if tgt in targets:
        hits.setdefault(tgt, []).append(pc)

for t in sorted(targets):
    print('target 0x%x : %d call sites' % (t, len(hits.get(t, []))))
    for pc in hits.get(t, []):
        print('   0x%x' % pc)
