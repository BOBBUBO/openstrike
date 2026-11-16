#!/usr/bin/env python3
"""Find ARM64 references (ADRP/ADD, ADRP/LDR) to given addresses.

Usage: python3 analysis/arm64_refs.py 0xADDR [0xADDR ...]
"""
import struct
import sys

SO = 'decompiled/native/lib/arm64-v8a/libGame.so'
LO, HI = 0x1dc0420, 0x5d008b4


def adrp_page(pc, w):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)


def main():
    targets = {int(a, 0) for a in sys.argv[1:]}
    d = open(SO, 'rb').read()
    reg = {}
    hits = []
    pc = LO
    while pc + 4 <= HI:
        w = struct.unpack_from('<I', d, pc)[0]
        op = w & 0xFFC00000
        if (w & 0x9F000000) == 0x90000000:
            reg[w & 31] = adrp_page(pc, w)
            pc += 4
            continue
        # ADD immediate (64-bit, same reg): dst = src + imm
        if op == 0x91000000:
            rd, rn = w & 31, (w >> 5) & 31
            imm = (w >> 10) & 0xFFF
            sh = (w >> 22) & 1
            if rn in reg:
                v = reg[rn] + (imm << (12 if sh else 0))
                reg[rd] = v
                if v in targets:
                    hits.append((pc, 'ADD', v))
            else:
                reg.pop(rd, None)
            pc += 4
            continue
        # LDR (unsigned imm, 64-bit) scaled by 8
        if (w & 0xFFC00000) == 0xF9400000:
            rd, rn = w & 31, (w >> 5) & 31
            off = ((w >> 10) & 0xFFF) * 8
            if rn in reg:
                v = reg[rn] + off
                if v in targets:
                    hits.append((pc, 'LDR', v))
            reg.pop(rd, None)          # LDR clobbers rd
            pc += 4
            continue
        # any other instruction that writes rd -> invalidate
        if (w & 0x1F000000) == 0x0B000000 or op in (0xD2800000, 0xF9000000,
                                                     0xB9000000, 0xAA000000,
                                                     0xD3400000, 0xD2800000):
            rd = w & 31
            reg.pop(rd, None)
        pc += 4
    for pc, kind, t in hits:
        print('0x%08x %s -> 0x%x' % (pc, kind, t))
    print('total', len(hits))


if __name__ == '__main__':
    main()
