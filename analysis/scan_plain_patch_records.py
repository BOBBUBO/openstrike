#!/usr/bin/env python3
"""Scan Patch.mpkinfo for named asset records and validate their archive metadata."""
import argparse
import json
import os
import re
import struct

# Typical Messiah asset names: path components and extension, no spaces.
PATH_RE = re.compile(rb"(?>[A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+\.[A-Za-z0-9_+-]+")
GUID_RE = re.compile(rb"^[0-9a-f]{2}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:\.[0-9]+)?$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mpkinfo")
    ap.add_argument("archives", nargs="+")
    ap.add_argument("--package-list")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    b = open(args.mpkinfo, "rb").read()
    known = None
    if args.package_list:
        known = set(json.load(open(args.package_list, encoding="utf-8")))
    bounds = []
    total = 0
    for path in args.archives:
        size = os.path.getsize(path)
        bounds.append((total, total + size, path))
        total += size
    rows = []
    for m in PATH_RE.finditer(b):
        path = m.group()
        if len(path) < 5 or GUID_RE.fullmatch(path):
            continue
        start, end = m.span()
        if start < 2:
            continue
        n = struct.unpack_from("<H", b, start - 2)[0]
        if n != len(path):
            continue
        q = end
        if q + 52 > len(b):
            continue
        stored = struct.unpack_from("<I", b, q)[0]
        md5_index = struct.unpack_from("<I", b, q + 4)[0]
        md5_kind = struct.unpack_from("<H", b, q + 8)[0]
        md5 = b[q + 10:q + 42]
        flags = struct.unpack_from("<H", b, q + 42)[0]
        offset = struct.unpack_from("<Q", b, q + 44)[0]
        logical = struct.unpack_from("<I", b, q + 52)[0]
        reserved = struct.unpack_from("<I", b, q + 56)[0]
        if not (0 < stored < 256 * 1024 * 1024):
            continue
        if md5_kind != 4 or not re.fullmatch(rb"[0-9a-f]{32}", md5):
            continue
        if flags != 0x100:
            continue
        if not (0 <= offset < total and stored <= total - offset):
            continue
        archive = next(x[2] for x in bounds if x[0] <= offset < x[1])
        rows.append({
            "index_offset": start - 2,
            "path": path.decode("ascii"),
            "stored_size": stored,
            "md5_index": md5_index,
            "md5": md5.decode(),
            "flags": flags,
            "archive_offset": offset,
            "archive": archive,
            "logical_size": logical,
            "reserved": reserved,
        })
    with open(args.output, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"found {len(rows)} named records")


if __name__ == "__main__":
    main()
