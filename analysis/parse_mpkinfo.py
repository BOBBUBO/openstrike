#!/usr/bin/env python3
"""Parse Messiah Patch.mpkinfo path/index records."""
import argparse
import json
import os
import struct


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("--output", required=True)
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0x2102)
    args = ap.parse_args()
    b = open(args.input, "rb").read()
    p = args.start
    rows = []
    while p + 62 <= len(b):
        n = struct.unpack_from("<H", b, p)[0]
        if not (1 <= n <= 4096):
            break
        q = p + 2
        path = b[q:q + n]
        q += n
        if any(x < 0x20 or x > 0x7e for x in path):
            break
        stored_size = struct.unpack_from("<Q", b, q)[0]
        q += 8
        md5_index = struct.unpack_from("<H", b, q)[0]
        q += 2
        md5 = b[q:q + 32].hex()
        q += 32
        flags = struct.unpack_from("<H", b, q)[0]
        q += 2
        archive_offset = struct.unpack_from("<Q", b, q)[0]
        q += 8
        logical_size = struct.unpack_from("<I", b, q)[0]
        q += 4
        reserved = b[q:q + 3]
        q += 3
        rows.append({
            "index_offset": p,
            "path": path.decode("ascii"),
            "stored_size": stored_size,
            "md5_index": md5_index,
            "md5": md5,
            "flags": flags,
            "archive_offset": archive_offset,
            "logical_size": logical_size,
            "reserved": reserved.hex(),
        })
        p = q
    with open(args.output, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"parsed {len(rows)} records; stopped at 0x{p:x}; next={b[p:p+16].hex()}")


if __name__ == "__main__":
    main()
