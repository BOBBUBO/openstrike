#!/usr/bin/env python3
"""Find all ADRP-based references (ADD/LDR/STR) to an exact target address."""
import struct, sys

SO = 'decompiled/native/lib/arm64-v8a/libGame.so'
LO, HI = 0x1dc0420, 0x5d008b4


def adrp_target(pc, w):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def clobber(w):
    """Return register written by w, or None."""
    op = w & 0xFFC00000
    if op in (0xD2800000, 0xAA000000, 0xD3400000, 0xB9000000, 0x92800000):
        return w & 31
    return None


def main():
    target = int(sys.argv[1], 0)
    d = open(SO, 'rb').read()
    reg = {}
    hits = []
    pc = LO
    while pc + 4 <= HI:
        w = struct.unpack_from('<I', d, pc)[0]
        if (w & 0x9F000000) == 0x90000000:
            reg[w & 31] = adrp_target(pc, w)
            pc += 4
            continue
        op = w & 0xFFC00000
        if op in (0xF9000000, 0xF9400000, 0x91000000, 0xD1000000):
            rn = (w >> 5) & 31
            off = ((w >> 10) & 0xfff) * (8 if (w >> 30) & 1 else 4)
            base = reg.get(rn)
            if base is not None and base + off == target:
                kind = {0xF9000000: 'STR', 0xF9400000: 'LDR', 0x91000000: 'ADDimm',
                        0xD1000000: 'SUBimm'}[op]
                hits.append((pc, kind))
            reg.pop(w & 31, None)
            pc += 4
            continue
        # ADD/SUB immediate (64-bit, base + imm12)
        if (w & 0x7F800000) == 0x11000000:
            rn = (w >> 5) & 31
            rd = w & 31
            base = reg.get(rn)
            imm = (w >> 10) & 0xfff
            sh = (w >> 22) & 1
            if sh:
                imm <<= 12
            if base is not None and base + imm == target:
                hits.append((pc, 'ADD' if not (w & 0x40000000) else 'SUB'))
            reg.pop(rd, None)
            pc += 4
            continue
        c = clobber(w)
        if c is not None:
            reg.pop(c, None)
        pc += 4
    for pc, kind in hits:
        print('0x%08x %s' % (pc, kind))
    print('total', len(hits))


main()
