#!/usr/bin/env python3
"""Search decompressed ZZZ4/LZ4 blocks in Messiah MPK files for needles and script signatures."""
import argparse
import collections
import hashlib
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
from lz4_block import decompress

PYC_MAGICS = {
    b"\x6f\x0d\x0d\x0a": "py3.11",
    b"\x55\x0d\x0d\x0a": "py3.10",
    b"\xa7\x0d\x0d\x0a": "py3.9",
    b"\x6f\x0c\x0d\x0a": "py3.8",
    b"\x16\x0d\x0d\x0a": "py3.7",
    b"\x42\x0d\x0d\x0a": "py3.6",
    b"\x03\x0d\x0d\x0a": "py3.5",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--needle", action="append", default=[])
    ap.add_argument("--jsonl")
    ap.add_argument("--save-dir")
    args = ap.parse_args()
    needles = [x.encode() for x in args.needle]
    outf = open(args.jsonl, "w", encoding="utf-8") if args.jsonl else None
    stats = collections.Counter()
    for path in args.files:
        with open(path, "rb") as f:
            data = f.read()
        pos = 0
        while True:
            z = data.find(b"ZZZ4", pos)
            if z < 0:
                break
            pos = z + 1
            if z < 0x20:
                continue
            f1 = struct.unpack_from("<I", data, z - 0x10)[0]
            f2 = struct.unpack_from("<I", data, z - 0x18)[0]
            if f2 != f1 + 8 or f1 < 24:
                continue
            csize = f1 - 24
            osize = struct.unpack_from("<I", data, z + 4)[0]
            if csize > len(data) - z - 8 or osize > 256 * 1024 * 1024:
                continue
            try:
                dec = decompress(data[z + 8:z + 8 + csize], osize)
            except Exception:
                stats["decompress_failed"] += 1
                continue
            stats["blocks"] += 1
            hits = [n.decode("utf-8", "replace") for n in needles if n in dec]
            pyc = next((v for k, v in PYC_MAGICS.items() if dec.startswith(k)), None)
            # Also look for a pyc header shortly after a small wrapper.
            if not pyc:
                for off in range(1, min(256, len(dec) - 3)):
                    pyc = next((v for k, v in PYC_MAGICS.items() if dec.startswith(k, off)), None)
                    if pyc:
                        pyc += f"+{off}"
                        break
            if hits or pyc:
                rec = {
                    "file": path,
                    "offset": z,
                    "compressed_size": csize,
                    "output_size": len(dec),
                    "md5": hashlib.md5(dec).hexdigest(),
                    "hits": hits,
                    "pyc": pyc,
                    "preview": "".join(chr(c) if 32 <= c < 127 else "." for c in dec[:128]),
                }
                print(json.dumps(rec, ensure_ascii=False))
                if outf:
                    outf.write(json.dumps(rec, ensure_ascii=False) + "\n")
                if args.save_dir:
                    os.makedirs(args.save_dir, exist_ok=True)
                    with open(os.path.join(args.save_dir, f"{os.path.basename(path)}_{z:010x}_{rec['md5']}.bin"), "wb") as f:
                        f.write(dec)
    if outf:
        outf.close()
    print("stats", stats, file=sys.stderr)


if __name__ == "__main__":
    main()
