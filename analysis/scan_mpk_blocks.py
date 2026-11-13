#!/usr/bin/env python3
"""Scan Messiah MPK-like files for ZZZ4/LZ4 blocks and summarize their contents."""
import argparse
import collections
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
from lz4_block import decompress


def classify(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if data.startswith(b"RIFF"):
        return "RIFF:" + data[8:12].decode("ascii", "replace")
    if data.startswith(b"PK\x03\x04"):
        return "ZIP"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP"
    if data.startswith(b"\xfd7zXZ"):
        return "XZ"
    if data.startswith(b"BKHD"):
        return "BKHD"
    if data.startswith(b"KTX\x20"):
        return "KTX"
    if data.startswith(b"RIFF"):
        return "RIFF"
    if data.startswith(b"\x00\x00\x00\x00") and len(data) >= 12:
        return "DDS?" if data[4:8] == b"DDS " else "ZERO"
    text = data[:512].lstrip(b"\x00 \t\r\n")
    if text.startswith((b"<?xml", b"<Root", b"<", b"{", b"[", b"import ", b"def ", b"class ", b"#!")):
        try:
            data[:4096].decode("utf-8")
            return "TEXT"
        except UnicodeDecodeError:
            pass
    return "BINARY"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out", help="JSONL output")
    ap.add_argument("--max-out", type=int, default=64 * 1024 * 1024)
    ap.add_argument("--save-dir")
    args = ap.parse_args()
    outf = open(args.out, "w", encoding="utf-8") if args.out else None
    total_in = total_out = blocks = 0
    classes = collections.Counter()
    for path in args.files:
        with open(path, "rb") as f:
            data = f.read()
        pos = 0
        found = []
        while True:
            z = data.find(b"ZZZ4", pos)
            if z < 0:
                break
            pos = z + 1
            if z < 0x20:
                continue
            # Valid block headers have payload_size and payload_size+8 fields.
            f1 = struct.unpack_from("<I", data, z - 0x10)[0]
            f2 = struct.unpack_from("<I", data, z - 0x18)[0]
            if f2 != f1 + 8 or f1 < 24:
                continue
            compressed_size = f1 - 24
            output_size = struct.unpack_from("<I", data, z + 4)[0]
            if compressed_size > len(data) - z - 8 or output_size > args.max_out:
                continue
            try:
                dec = decompress(data[z + 8:z + 8 + compressed_size], output_size)
            except Exception as e:
                continue
            blocks += 1
            total_in += compressed_size
            total_out += len(dec)
            kind = classify(dec)
            classes[kind] += 1
            md5 = hashlib.md5(dec).hexdigest()
            preview = "".join(chr(c) if 32 <= c < 127 else "." for c in dec[:48])
            rec = {
                "file": path,
                "offset": z,
                "compressed_size": compressed_size,
                "output_size": len(dec),
                "md5": md5,
                "kind": kind,
                "preview": preview,
            }
            if outf:
                import json
                outf.write(json.dumps(rec, ensure_ascii=False) + "\n")
            if args.save_dir and kind in {"TEXT", "PNG", "JPEG", "ZIP", "GZIP", "XZ", "KTX", "BKHD"}:
                os.makedirs(args.save_dir, exist_ok=True)
                ext = kind.lower().replace(":", "_")
                with open(os.path.join(args.save_dir, f"{z:010x}_{md5}.{ext}"), "wb") as f:
                    f.write(dec)
    if outf:
        outf.close()
    print(f"blocks={blocks} compressed={total_in} decompressed={total_out}")
    print("classes", classes)


if __name__ == "__main__":
    main()
