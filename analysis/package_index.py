#!/usr/bin/env python3
"""Resolve every file in the Android package (`Resources1.mpk`) to its byte offset.

Two independent tables are needed:

* `Resources.mpkinfo` — 45,489 × 20-byte records
      u8 kind | u8 path_suffix[3] | u32 digest0 | u32 offset | u32 size | u32 flags
  `path_suffix` is the last 3 characters of the file path, `offset` is the
  **global byte offset of the file body inside Resources1.mpk** (verified: the
  record for `essential_py3` points at a blob whose MD5 is exactly the MD5
  published in the pack manifest), `size` is the file length.

* the *pack manifest* inside Resources1.mpk (`<32 hex>!|{ ... }`)
      { "common": {name: [md5, size]}, "android_common": {...},
        "android_astc_512": {...} }

Joining the two on (path_suffix, size) yields name → offset.
"""
import hashlib
import json
import os
import re
import struct
import sys

PKG = "decompiled/apk/split_base_mpk/assets/Resources1.mpk"
MANIFEST_OFF = 0x0C172479


def load_pack_manifest(data):
    """Parse `<32 hex>!|{ <json> }` starting at MANIFEST_OFF."""
    o = MANIFEST_OFF
    assert data[o + 32:o + 34] == b"!|", "bad manifest magic"
    start = o + 35                      # skip "!|{"
    depth = 0
    ins = False
    esc = False
    i = start
    while i < len(data):
        ch = data[i]
        if ins:
            if esc:
                esc = False
            elif ch == 0x5C:
                esc = True
            elif ch == 0x22:
                ins = False
        else:
            if ch == 0x22:
                ins = True
            elif ch == 0x7B:
                depth += 1
            elif ch == 0x7D:
                depth -= 1
                if depth == 0:
                    return json.loads(data[start:i + 1])
        i += 1
    raise ValueError("manifest not terminated")


def load_mpkinfo(path="analysis/resources-mpkinfo.jsonl"):
    recs = []
    with open(path) as fh:
        for line in fh:
            r = json.loads(line)
            recs.append({
                "index": r["index"],
                "kind": r["kind"],
                "suffix": r["path_suffix"],
                "digest0": r["digest_words"][0],
                "offset": r["digest_words"][1],
                "size": r["logical_size"],
                "flags": r["flags"],
            })
    return recs


def build_index(recs, manifest):
    """name -> {md5,size,offset,kind,flags,suffix}"""
    by_ss = {}
    for r in recs:
        by_ss.setdefault((r["suffix"], r["size"]), []).append(r)

    index = {}
    ambiguous = 0
    missing = 0
    for section in manifest.get("file_sections", []):
        for name, (md5, size) in manifest.get(section, {}).items():
            cands = by_ss.get((name[-3:], size), [])
            if len(cands) == 1:
                r = cands[0]
                index[name] = {
                    "md5": md5, "size": size, "offset": r["offset"],
                    "kind": r["kind"], "flags": r["flags"],
                    "suffix": r["suffix"], "section": section,
                    "mpkinfo_index": r["index"],
                }
            elif len(cands) > 1:
                ambiguous += 1
                index[name] = {
                    "md5": md5, "size": size, "offset": None,
                    "candidates": [c["offset"] for c in cands],
                    "section": section,
                }
            else:
                missing += 1
    return index, ambiguous, missing


def main():
    data = open(PKG, "rb").read()
    manifest = load_pack_manifest(data)
    recs = load_mpkinfo()
    index, ambiguous, missing = build_index(recs, manifest)
    total = sum(len(manifest.get(s, {})) for s in manifest.get("file_sections", []))
    resolved = sum(1 for v in index.values() if v.get("offset") is not None)
    print("package files listed        : %d" % total)
    print("resolved to a unique offset  : %d" % resolved)
    print("ambiguous (several matches)  : %d" % ambiguous)
    print("no (suffix,size) match       : %d" % missing)
    json.dump(index, open("analysis/package-index.json", "w"))

    # verify the resolution by re-hashing the bytes at the computed offsets
    print()
    print("verifying resolved files against their manifest MD5 ...")
    ok = bad = 0
    failures = []
    for name, v in index.items():
        off = v.get("offset")
        if off is None:
            continue
        blob = data[off:off + v["size"]]
        if hashlib.md5(blob).hexdigest() == v["md5"]:
            ok += 1
        else:
            bad += 1
            if len(failures) < 10:
                failures.append((name, off, v["size"], v["md5"],
                                 hashlib.md5(blob).hexdigest()))
    print("md5 verified : %d" % ok)
    print("md5 mismatch : %d" % bad)
    for f in failures:
        print("   ", f)


if __name__ == "__main__":
    main()
