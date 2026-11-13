#!/usr/bin/env python3
"""Find accesses to the Cython globals pages (0x73cc000-0x73ce000)."""
import struct, sys
d = open('decompiled/native/lib/arm64-v8a/libGame.so', 'rb').read()
LO, HI = int(sys.argv[1], 0), int(sys.argv[2], 0)
PAGES = (0x73cc000, 0x73cd000, 0x73ce000, 0x73cb000)

def adrp_page(pc, w):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

adrp = {}
out = []
pc = LO
while pc + 4 <= HI:
    w = struct.unpack_from('<I', d, pc)[0]
    pg = adrp_page(pc, w)
    if pg is not None:
        adrp[w & 31] = pg
    elif (w & 0xFFC00000) in (0xF9000000, 0xF9400000):
        rn = (w >> 5) & 31
        off = ((w >> 10) & 0xFFF) * 8
        b = adrp.get(rn)
        if b in PAGES:
            out.append((pc, 'STR' if (w & 0xFFC00000) == 0xF9000000 else 'LDR', b, off, b + off, w & 31))
    pc += 4
print('accesses:', len(out))
for o in out:
    print('  0x%08x %s base=0x%x off=%d -> 0x%x rt=x%d' % o)
