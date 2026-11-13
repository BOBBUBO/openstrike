#!/usr/bin/env python3
"""Scan Patch.mpkinfo for full GUID patch records by validating their archive offsets."""
import argparse
import json
import os
import re
import struct

GUID_PATH = re.compile(rb"^[0-9a-f]{2}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:\.[0-9]+)?$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mpkinfo")
    ap.add_argument("archives", nargs="+")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    b = open(args.mpkinfo, "rb").read()
    bounds = []
    total = 0
    for path in args.archives:
        size = os.path.getsize(path)
        bounds.append((total, total + size, path))
        total += size
    rows = []
    for m in re.finditer(rb"[0-9a-f]{2}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:\.[0-9]+)?", b):
        start, end = m.span()
        if start < 2:
            continue
        n = struct.unpack_from("<H", b, start - 2)[0]
        if n != len(m.group()):
            continue
        q = end
        if q + 57 > len(b):
            continue
        stored = struct.unpack_from("<Q", b, q)[0]
        md5_index = struct.unpack_from("<H", b, q + 8)[0]
        md5 = b[q + 10:q + 42]
        flags = struct.unpack_from("<H", b, q + 42)[0]
        offset = struct.unpack_from("<Q", b, q + 44)[0]
        logical = struct.unpack_from("<I", b, q + 52)[0]
        reserved = b[q + 56:q + 59]
        if not (0 < stored < 256 * 1024 * 1024):
            continue
        if not re.fullmatch(rb"[0-9a-f]{32}", md5):
            continue
        if flags not in (0, 0x100, 0x101, 0x200, 0x300):
            continue
        if not (0 <= offset < total and stored <= total - offset):
            continue
        archive = next(x[2] for x in bounds if x[0] <= offset < x[1])
        rows.append({
            "index_offset": start - 2,
            "path": m.group().decode(),
            "stored_size": stored,
            "md5_index": md5_index,
            "md5": md5.decode(),
            "flags": flags,
            "archive_offset": offset,
            "archive": archive,
            "logical_size": logical,
            "reserved": reserved.hex(),
        })
    with open(args.output, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"found {len(rows)} records")


if __name__ == "__main__":
    main()
