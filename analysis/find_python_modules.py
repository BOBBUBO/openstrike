#!/usr/bin/env python3
"""Recover the native Python extension-module registration table.

Scans backwards from each call to the PyImport_AppendInittab wrapper and
reconstructs the argument registers (x0 = module name, x1 = PyModuleDef).
"""
import struct
import sys

ELF = 'decompiled/native/lib/arm64-v8a/libGame.so'
data = open(ELF, 'rb').read()
TEXT_START = 0x1DC0420
TEXT_END = 0x5D008B4


def sx(v, bits):
    s = 1 << (bits - 1)
    return (v ^ s) - s


def reg_value(pc, regs, reg):
    """Value of `reg` at instruction pc using tracked regs dict."""
    return regs.get(reg)


def cstr(off, maxlen=80):
    try:
        e = data.index(b'\0', off)
    except ValueError:
        return None
    s = data[off:e][:maxlen]
    try:
        return s.decode('utf-8')
    except UnicodeDecodeError:
        return repr(s)


def backscan(pc, back=96):
    """Return {reg: value} for the instructions in [pc-back, pc)."""
    regs = {}
    start = pc - back
    for q in range(start, pc, 4):
        ins = struct.unpack_from('<I', data, q)[0]
        rd = ins & 31
        # ADRP
        if ins & 0x9F000000 == 0x90000000:
            immlo = (ins >> 29) & 3
            immhi = (ins >> 5) & 0x7FFFF
            page = (q & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)
            regs[rd] = page
            continue
        # ADR
        if ins & 0x9F000000 == 0x10000000:
            immlo = (ins >> 29) & 3
            immhi = (ins >> 5) & 0x7FFFF
            regs[rd] = (q & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)
            continue
        # ADD imm
        if (ins & 0xFFC00000) == 0x91000000:
            rn = (ins >> 5) & 31
            imm = (ins >> 10) & 0xFFF
            sh = (ins >> 22) & 1
            if rn in regs:
                regs[rd] = regs[rn] + (imm << (12 if sh else 0))
            continue
        # MOV reg, reg
        if (ins & 0xFFE0FFE0) == 0xAA0003E0:
            rm = (ins >> 16) & 31
            if rm in regs:
                regs[rd] = regs[rm]
            continue
    return regs


def main():
    targets = {int(x, 0) for x in sys.argv[1:]}
    for pc in range(TEXT_START, TEXT_END - 3, 4):
        insn = struct.unpack_from('<I', data, pc)[0]
        if insn & 0xFC000000 != 0x94000000:
            continue
        imm = insn & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        if pc + (imm << 2) not in targets:
            continue
        regs = backscan(pc)
        name = regs.get(0)
        d = regs.get(1)
        print('0x%x  name=%-28s def=0x%x' % (
            pc, cstr(name) if name else '?', d if d else 0))


if __name__ == '__main__':
    main()
