#!/usr/bin/env python3
"""Extract indexed assets from Messiah Patch*.mpk archives.

The Patch.mpkinfo GUID records provide a global archive offset and stored byte
count.  Some entries are stored raw; others use the MPK file wrapper.  In the
wrapper, ZZZ4 is an LZ4 block (magic, u32 output size, compressed bytes), while
NNNN is an already encoded/raw texture payload.

A number of earlier scans reported a separate ``ZZZZ`` compression type.  That
was a false positive: the engine compares the first word against 0x345a5a5a
(the bytes ``ZZZ4``), and decodes it with LZ4_decompress_safe just like ZZZ4.
``ZZZZ`` occurrences are random data inside compressed or texture payloads.
"""
import argparse
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
from lz4_block import decompress_with_consumed

MPK_MAGIC = b"\x02\x02\x02\x01\x01\x2b"
MESSIAH_MAGIC = b".MESSIAH"
GLOBAL_ARCHIVES = [
    "Patch.mpk", "Patch1.mpk", "Patch2.mpk", "Patch3.mpk",
    "Patch4.mpk", "Patch5.mpk", "Patch6.mpk", "Patch7.mpk",
]


class ArchiveMap:
    def __init__(self, patch_dir):
        self.entries = []
        base = 0
        for name in GLOBAL_ARCHIVES:
            path = os.path.join(patch_dir, name)
            if not os.path.exists(path):
                continue
            size = os.path.getsize(path)
            self.entries.append((base, base + size, path))
            base += size
        self.total = base

    def locate(self, global_offset):
        for start, end, path in self.entries:
            if start <= global_offset < end:
                return path, global_offset - start
        raise ValueError(f"global offset 0x{global_offset:x} is outside archives")


def decode_messiah(raw):
    """Decode a ``.MESSIAH`` container (patch hot-patch material records).

    Layout:  char magic[8] ".MESSIAH"; u32 kind; body.
    kind 1 = float/material property blob, kind 2 = (u16 len, name) table.
    """
    if len(raw) < 12:
        raise ValueError("truncated .MESSIAH header")
    kind = struct.unpack_from("<I", raw, 8)[0]
    body = raw[12:]
    details = {"messiah_kind": kind, "messiah_body_len": len(body)}
    if kind == 2:
        # body = u16 len + name, then repeated (u8 tag=1, u16 len + name),
        # then a u32 and one final (u16 len + text) property blob.
        names = []
        i = 0
        while i + 2 <= len(body):
            n = struct.unpack_from("<H", body, i)[0]
            i += 2
            if i + n > len(body):
                break
            if n:
                names.append(body[i:i + n].decode("utf-8", "replace"))
            i += n
            if i >= len(body):
                break
            tag = body[i]
            if tag == 0x01:
                i += 1
                continue
            if tag == 0x00 and i + 5 <= len(body):
                i += 4          # u32 counter
                continue
            break
        details["names"] = names
    return body, "messiah-%d" % kind, details


def decode_entry(raw):
    """Return (payload, kind, details)."""
    if raw.startswith(MESSIAH_MAGIC):
        return decode_messiah(raw)
    if not raw.startswith(MPK_MAGIC):
        return raw, "raw", {}
    if len(raw) < 0x3C:
        return raw, "raw-truncated-wrapper", {}
    magic = raw[0x38:0x3C]
    if magic == b"ZZZ4":
        if len(raw) < 0x40:
            raise ValueError("truncated ZZZ4 header")
        output_size = struct.unpack_from("<I", raw, 0x3C)[0]
        # The two size words immediately before the magic include fixed
        # metadata.  The compressed stream itself is everything after magic
        # and output_size.
        compressed = raw[0x40:]
        payload, consumed = decompress_with_consumed(compressed, output_size)
        details = {
            "compressed_size": len(compressed),
            "compressed_consumed": consumed,
            "output_size": output_size,
            # A patch record carries exactly one chunk: the LZ4 stream always
            # consumes the remainder of the stored record.  Earlier "multi
            # chunk" statistics were false positives caused by ZZZ4/NNNN byte
            # sequences occurring inside the compressed payload itself.
            "chunks": 1,
            "trailing_bytes": len(compressed) - consumed,
        }
        return payload, "lz4-block", details
    if magic == b"ZZZZ":
        # Not a distinct engine compression type.  ZZZZ is the byte-reversed
        # spelling of the ZZZ4 magic and appears naturally in binary payloads.
        return raw, "unknown-wrapper", {
            "magic_hex": magic.hex(),
            "note": "ZZZZ is not an engine compression marker",
        }
    if magic == b"NNNN":
        # NNNN is an already encoded texture block (for example ASTC/ETC).
        # Preserve its bytes exactly; the descriptor remains in the manifest.
        return raw[0x3C:], "encoded-texture", {
            "payload_size": len(raw) - 0x3C,
            "descriptor_hex": raw[0x20:0x38].hex(),
        }
    return raw, "unknown-wrapper", {"magic_hex": magic.hex()}


def safe_name(path):
    path = path.replace("\\", "/")
    while path.startswith("/"):
        path = path[1:]
    parts = []
    for part in path.split("/"):
        if part in ("", ".", ".."):
            continue
        parts.append(part)
    return os.path.join(*parts) if parts else "unnamed"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--patch-dir", required=True)
    ap.add_argument("--records", action="append", required=True,
                    help="JSONL record file (repeatable)")
    ap.add_argument("--output", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--path", action="append", default=[],
                    help="exact indexed path (repeatable)")
    ap.add_argument("--path-prefix", action="append", default=[])
    ap.add_argument("--category", action="append", default=[],
                    help="patchlist category prefix, e.g. dlcid_icon")
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--all", action="store_true", help="extract every selected entry")
    args = ap.parse_args()

    archives = ArchiveMap(args.patch_dir)
    category_by_path = {}
    patchlist = os.path.join(args.patch_dir, "spike_patchlist_android_astc_512_py3.txt")
    if os.path.exists(patchlist):
        data = json.load(open(patchlist, encoding="utf-8"))
        for category, values in data.items():
            if not isinstance(values, list):
                continue
            for value in values:
                if isinstance(value, str):
                    category_by_path.setdefault(value, category)

    wanted = set(args.path)
    rows = []
    seen = set()
    for record_file in args.records:
        for line in open(record_file, encoding="utf-8"):
            row = json.loads(line)
            key = (row.get("archive_offset"), row.get("path"))
            if key in seen:
                continue
            seen.add(key)
            path = row["path"]
            category = category_by_path.get(path)
            if wanted and path not in wanted:
                continue
            if args.path_prefix and not any(path.startswith(p) for p in args.path_prefix):
                continue
            if args.category:
                if category is None:
                    continue
                if not any(category.startswith(p) for p in args.category):
                    continue
            rows.append(row)
            if not args.all and len(rows) >= args.limit:
                break
        if not args.all and len(rows) >= args.limit:
            break

    os.makedirs(args.output, exist_ok=True)
    manifest = open(args.manifest, "w", encoding="utf-8")
    stats = {}
    failures = 0
    for row in rows:
        archive_path, local_offset = archives.locate(row["archive_offset"])
        stored_size = row["stored_size"]
        with open(archive_path, "rb") as f:
            f.seek(local_offset)
            raw = f.read(stored_size)
        if len(raw) != stored_size:
            failures += 1
            continue
        try:
            payload, kind, details = decode_entry(raw)
        except Exception as exc:
            failures += 1
            rec = dict(row)
            rec.update({"status": "decode-failed", "error": str(exc),
                        "archive_local_offset": local_offset})
            manifest.write(json.dumps(rec, ensure_ascii=False) + "\n")
            continue
        out_path = os.path.join(args.output, safe_name(row["path"]))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(payload)
        actual_md5 = hashlib.md5(payload).hexdigest()
        rec = dict(row)
        rec.update({
            "status": "ok",
            "kind": kind,
            "archive_local_offset": local_offset,
            "archive_file": archive_path,
            "output_path": out_path,
            "output_size": len(payload),
            "output_md5": actual_md5,
            "md5_matches": actual_md5 == row.get("md5"),
            "category": category_by_path.get(row["path"]),
        })
        rec.update(details)
        manifest.write(json.dumps(rec, ensure_ascii=False) + "\n")
        stats[kind] = stats.get(kind, 0) + 1
    manifest.close()
    print(json.dumps({"selected": len(rows), "written": sum(stats.values()),
                      "failures": failures, "kinds": stats}, ensure_ascii=False))


if __name__ == "__main__":
    main()
