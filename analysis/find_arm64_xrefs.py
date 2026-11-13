#!/usr/bin/env python3
"""Find ARM64 ADRP/ADD (and ADRP/LDR) references to addresses in an ELF64 file."""
import argparse
import struct
import sys


def sx(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("targets", nargs="+", help="target virtual addresses, decimal or 0x-prefixed")
    ap.add_argument("--text-start", type=lambda x: int(x, 0))
    ap.add_argument("--text-end", type=lambda x: int(x, 0))
    ap.add_argument("--window", type=int, default=12)
    args = ap.parse_args()

    targets = {int(x, 0) for x in args.targets}
    with open(args.elf, "rb") as f:
        data = f.read()

    start = args.text_start if args.text_start is not None else 0x1DC0420
    end = args.text_end if args.text_end is not None else min(len(data), 0x5D008B4)

    for pc in range(start, end - 3, 4):
        insn = struct.unpack_from("<I", data, pc)[0]
        if insn & 0x9F000000 != 0x90000000:  # ADRP
            continue
        rd = insn & 31
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        page = (pc & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)
        for delta in range(4, args.window * 4 + 1, 4):
            q = pc + delta
            if q >= end - 3:
                break
            n = struct.unpack_from("<I", data, q)[0]
            # ADD Xd, Xn, #imm12
            if n & 0x7F800000 == 0x11000000 and (n & 31) == rd and ((n >> 5) & 31) == rd:
                addr = page + ((n >> 10) & 0xFFF)
                if addr in targets:
                    print(f"ADD  0x{pc:x} -> 0x{q:x}: target 0x{addr:x}")
            # LDR Xt, [Xn, #imm12]*{scale}; base must be ADRP register
            if n & 0x3B000000 == 0x39000000 and ((n >> 5) & 31) == rd:
                scale = 3 if n & (1 << 30) else 2
                addr = page + (((n >> 10) & 0xFFF) << scale)
                if addr in targets:
                    print(f"LDR  0x{pc:x} -> 0x{q:x}: target 0x{addr:x}")


if __name__ == "__main__":
    main()
