#!/usr/bin/env python3
"""Parse the Resources.mpkinfo sidecar shipped in split_base_mpk.apk.

The format is a compact, fixed-record hash index:

    u32 version
    u32 record_count
    record[record_count]              # 20 bytes each
    u8  md5_digest[16]                # MD5 of header + records

Each record is:

    u8  resource_kind
    u8  path_suffix[3]                # last three characters of the path
    u32 digest_part_0
    u32 digest_part_1
    u32 logical_size
    u32 flags

The digest parts are the first eight bytes of the resource MD5 in the file's
native little-endian word order.  The final 16-byte sidecar digest covers all
preceding bytes.
"""
import argparse
import hashlib
import json
import struct
import sys


def parse(data):
    if len(data) < 24:
        raise ValueError("file is too short")
    version, count = struct.unpack_from("<II", data, 0)
    records_end = 8 + count * 20
    if records_end + 16 > len(data):
        raise ValueError(
            f"truncated index: need {records_end + 16} bytes, have {len(data)}")
    digest = data[records_end:records_end + 16]
    expected = hashlib.md5(data[:records_end]).digest()
    if digest != expected:
        raise ValueError(
            f"index MD5 mismatch: expected {expected.hex()}, got {digest.hex()}")

    records = []
    for i in range(count):
        offset = 8 + i * 20
        kind = data[offset]
        suffix = data[offset + 1:offset + 4].decode("ascii", "replace")
        digest0, digest1, size, flags = struct.unpack_from("<IIII", data, offset + 4)
        records.append({
            "index": i,
            "index_offset": offset,
            "kind": kind,
            "path_suffix": suffix,
            "digest_words": [digest0, digest1],
            "digest_hex": f"{digest0:08x}{digest1:08x}",
            "logical_size": size,
            "flags": flags,
        })
    return {
        "version": version,
        "count": count,
        "records_end": records_end,
        "index_md5": digest.hex(),
        "index_md5_valid": True,
        "records": records,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("--jsonl", help="write one parsed record per line")
    ap.add_argument("--summary", help="write a JSON summary")
    args = ap.parse_args()
    with open(args.input, "rb") as f:
        data = f.read()
    parsed = parse(data)
    records = parsed.pop("records")
    if args.jsonl:
        with open(args.jsonl, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
    if args.summary:
        with open(args.summary, "w", encoding="utf-8") as f:
            json.dump(parsed, f, indent=2)
    json.dump(parsed, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
