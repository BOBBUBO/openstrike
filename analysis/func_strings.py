#!/usr/bin/env python3
"""List every rodata string constant referenced by an ARM64 function range.

Cython (and the engine) reference string constants with ADRP+ADD.  This
tool decodes those pairs and prints the referenced C strings, which is the
fastest way to read a compiled Python function's vocabulary.

Usage: python3 analysis/func_strings.py 0xSTART 0xEND
"""
import re
import struct
import sys

SO = 'decompiled/native/lib/arm64-v8a/libGame.so'


def adrp_page(pc, w):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)


def cstr(d, v, maxlen=200):
    if not (0 < v < len(d)):
        return None
    e = d.find(b'\0', v, v + maxlen)
    if e < 0:
        return None
    try:
        s = d[v:e].decode('utf-8')
    except UnicodeDecodeError:
        return None
    if not s or not re.fullmatch(r'[\x20-\x7e]+', s):
        return None
    return s


def main():
    lo, hi = int(sys.argv[1], 0), int(sys.argv[2], 0)
    d = open(SO, 'rb').read()
    reg = {}
    seen = []
    pc = lo
    while pc + 4 <= hi:
        w = struct.unpack_from('<I', d, pc)[0]
        op = w & 0xFFC00000
        if (w & 0x9F000000) == 0x90000000:
            reg[w & 31] = adrp_page(pc, w)
            pc += 4
            continue
        if op == 0x91000000:
            rd, rn = w & 31, (w >> 5) & 31
            imm = (w >> 10) & 0xFFF
            sh = (w >> 22) & 1
            if rn in reg:
                v = reg[rn] + (imm << (12 if sh else 0))
                reg[rd] = v
                s = cstr(d, v)
                if s:
                    seen.append((pc, v, s))
            else:
                reg.pop(rd, None)
            pc += 4
            continue
        if (w & 0xFFC00000) == 0xF9400000:
            rd, rn = w & 31, (w >> 5) & 31
            off = ((w >> 10) & 0xFFF) * 8
            if rn in reg:
                v = reg[rn] + off
                s = cstr(d, v)
                if s:
                    seen.append((pc, v, s))
            reg.pop(rd, None)
            pc += 4
            continue
        if (w & 0x1F000000) == 0x0B000000 or op in (
                0xD2800000, 0xF9000000, 0xB9000000, 0xAA000000, 0xD3400000):
            reg.pop(w & 31, None)
        pc += 4
    for pc, v, s in seen:
        print('0x%08x  0x%x  %r' % (pc, v, s))


if __name__ == '__main__':
    main()
