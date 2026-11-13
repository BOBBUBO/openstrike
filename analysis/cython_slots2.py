#!/usr/bin/env python3
"""Improved Cython interned-string slot resolver.

Improvement over cython_string_slots.py: the ADRP base register is not assumed
to be x8.  We track the page value of every register that has been set by an
ADRP, then recognise
    ADD  xd, xn, #imm   with page[xn] == SLOT_BASE   -> slot address
    ADD  xd, xn, #imm   with page[xn] in .rodata      -> literal address
and pair the resulting sp-offset slots up to obtain literal -> global slot.
"""
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


def adrp_page(pc, i):
    if i & 0x9F000000 != 0x90000000:
        return None
    immlo = (i >> 29) & 3
    immhi = (i >> 5) & 0x7FFFF
    return (pc & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)


def is_add_imm(i):
    return i & 0x7F000000 == 0x11000000 and not (i & 0x20000000)


def is_str_sp(i):
    return (i & 0xFFC003E0) == 0xF90003E0 and ((i >> 5) & 31) == 31


RODATA = (0x580000, 0xA80000)

page = {}           # register -> page value
slot_sp = {}        # sp offset -> slot address
lit_sp = {}         # sp offset -> literal address

for pc in range(LO, HI, 4):
    i = prog[pc]
    if i & 0x9F000000 == 0x90000000:
        rd = i & 31
        p = adrp_page(pc, i)
        if p is not None:
            page[rd] = p
        continue
    if not is_add_imm(i):
        continue
    rd = i & 31
    rn = (i >> 5) & 31
    imm = (i >> 10) & 0xFFF
    base = page.get(rn)
    if base is None:
        continue
    target = BASE + imm if (base & ~0xFFF) == (BASE & ~0xFFF) else base + imm
    kind = None
    if (base & ~0xFFF) == (BASE & ~0xFFF) and BASE - 0x4000 <= target <= BASE + 0x4000:
        kind = 'slot'
    elif RODATA[0] <= base < RODATA[1]:
        kind = 'lit'
    if kind is None:
        continue
    # look ahead for "str x<rd>, [sp, #off]"
    for d in range(4, 32, 4):
        j = prog.get(pc + d)
        if j is None:
            break
        if is_str_sp(j) and (j & 31) == rd:
            off = ((j >> 10) & 0xFFF) * 8
            (slot_sp if kind == 'slot' else lit_sp)[off] = target
            break

pairs = {}
for off, s in slot_sp.items():
    for delta in (-8, 8, -16, 16):
        if off + delta in lit_sp:
            pairs.setdefault(lit_sp[off + delta], s)
            break

out = open('analysis/cython-string-slots2.txt', 'w')
out.write('base=%x slots=%d lits=%d pairs=%d\n' % (BASE, len(slot_sp), len(lit_sp), len(pairs)))
for lit, slot in sorted(pairs.items()):
    s = data[lit:lit + 96]
    s = s[:s.index(b'\0')] if b'\0' in s else s
    out.write('0x%x -> slot 0x%x   %r\n' % (lit, slot, s))
out.close()
print('slot_sp=%d lit_sp=%d pairs=%d' % (len(slot_sp), len(lit_sp), len(pairs)))
for lit, slot in sorted(pairs.items()):
    s = data[lit:lit + 64]
    s = s[:s.index(b'\0')] if b'\0' in s else s
    print('0x%08x -> 0x%08x  %r' % (lit, slot, s))
