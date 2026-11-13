#!/usr/bin/env python3
"""Recover Cython's interned-string global slot addresses (linear scan)."""
import struct
import sys

ELF = sys.argv[1] if len(sys.argv) > 1 else 'decompiled/native/lib/arm64-v8a/libGame.so'
LO = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x3A56A9C
HI = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x3A60000
BASE = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x73CCBA8

data = open(ELF, 'rb').read()
prog = {pc: struct.unpack_from('<I', data, pc)[0] for pc in range(LO, HI, 4)}


def sx(v, bits):
    s = 1 << (bits - 1)
    return (v ^ s) - s


def is_adrp(i):
    return i & 0x9F000000 == 0x90000000


def is_add_imm(i):
    return i & 0x7F000000 == 0x11000000 and not (i & 0x20000000)


def is_str_sp(i):
    # STR (immediate, unsigned offset), 64-bit, base=SP
    return (i & 0xFFC003E0) == 0xF90003E0 and ((i >> 5) & 31) == 31


def is_ldr_any(i):
    return i & 0x3B000000 == 0x39000000


slot_stores = {}   # sp-offset -> K
lit_stores = {}    # sp-offset -> literal address
for pc in range(LO, HI, 4):
    i = prog[pc]
    if is_add_imm(i):
        rd = i & 31
        rn = (i >> 5) & 31
        imm = (i >> 10) & 0xFFF
        if rn == 8:
            for d in range(4, 24, 4):
                j = prog.get(pc + d)
                if j is None:
                    break
                if is_str_sp(j) and (j & 31) == rd:
                    off = ((j >> 10) & 0xFFF) * 8
                    slot_stores[off] = imm
                    break
    elif is_adrp(i):
        rd = i & 31
        immlo = (i >> 29) & 3
        immhi = (i >> 5) & 0x7FFFF
        page = (pc & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)
        for d in range(4, 24, 4):
            j = prog.get(pc + d)
            if j is None:
                break
            if is_add_imm(j) and ((j >> 5) & 31) == rd:
                lit = page + ((j >> 10) & 0xFFF)
                if 0xA60000 <= lit < 0xA80000:
                    for d2 in range(4, 24, 4):
                        k = prog.get(pc + d + d2)
                        if k is None:
                            break
                        if is_str_sp(k) and (k & 31) == rd:
                            off = ((k >> 10) & 0xFFF) * 8
                            lit_stores[off] = lit
                            break
                break

slot_of_literal = {}
for off, lit in lit_stores.items():
    if off - 8 in slot_stores:
        slot_of_literal[lit] = BASE + slot_stores[off - 8]

out = open('analysis/cython-string-slots.txt', 'w')
out.write('base=%x  slot_stores=%d lit_stores=%d entries=%d\n'
          % (BASE, len(slot_stores), len(lit_stores), len(slot_of_literal)))
for lit, slot in sorted(slot_of_literal.items()):
    s = data[lit:lit + 64]
    s = s[:s.index(b'\0')] if b'\0' in s else s
    out.write('0x%x -> slot 0x%x   %r\n' % (lit, slot, s))
out.close()
print('entries', len(slot_of_literal))
