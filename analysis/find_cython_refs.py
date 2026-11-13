#!/usr/bin/env python3
"""Locate Cython-generated code that references a given .rodata string-table range.

Cython emits, for every module, an init function that creates all string
constants via __Pyx_PyUnicode_FromString(<literal>); those calls show up as
ADRP+ADD pairs targeting the module's string table.  The module's own
functions are emitted immediately before that init function.
"""
import argparse
import struct
from collections import defaultdict


def sx(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--lo", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--hi", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--text-start", type=lambda x: int(x, 0), default=0x1DC0420)
    ap.add_argument("--text-end", type=lambda x: int(x, 0), default=0x5D008B4)
    ap.add_argument("--bucket", type=lambda x: int(x, 0), default=0x1000)
    args = ap.parse_args()

    data = open(args.elf, "rb").read()
    hits = defaultdict(list)
    start, end = args.text_start, args.text_end
    for pc in range(start, end - 3, 4):
        insn = struct.unpack_from("<I", data, pc)[0]
        if insn & 0x9F000000 != 0x90000000:
            continue
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        page = (pc & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)
        for delta in range(4, 60, 4):
            q = pc + delta
            if q >= end - 3:
                break
            i2 = struct.unpack_from("<I", data, q)[0]
            if i2 & 0x7F000000 == 0x11000000:  # ADD (immediate)
                if i2 & 0x20000000:  # shift
                    continue
                imm = (i2 >> 10) & 0xFFF
                rn = (i2 >> 5) & 31
                rd = i2 & 31
                if rn != (insn & 31):
                    continue
                addr = page + imm
                if args.lo <= addr <= args.hi:
                    hits[pc].append((q, addr))
    out = open("analysis/cython-xrefs.txt", "w")
    buckets = defaultdict(int)
    for pc, lst in hits.items():
        buckets[pc & ~(args.bucket - 1)] += len(lst)
    out.write("total xref sites: %d\n" % len(hits))
    for b, c in sorted(buckets.items(), key=lambda kv: -kv[1])[:40]:
        out.write("bucket %s : %d refs\n" % (hex(b), c))
    out.write("\n--- per-site detail (top 200 by bucket) ---\n")
    byb = defaultdict(list)
    for pc, lst in hits.items():
        byb[pc & ~(args.bucket - 1)].append((pc, lst))
    for b, c in sorted(byb.items(), key=lambda kv: -len(kv[1]))[:12]:
        out.write("\n== bucket %s (%d sites)\n" % (hex(b), len(c)))
        for pc, lst in sorted(c):
            tgts = ", ".join("%x" % a for _, a in lst)
            out.write("  %x -> %s\n" % (pc, tgts))
    out.close()
    print("done")


if __name__ == "__main__":
    main()
