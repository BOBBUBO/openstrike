#!/usr/bin/env python3
"""Walk every ZZZ4 (LZ4) chunk inside a package/patch mpk and search the
decompressed payloads.

The framing is the same as the patch side:
    magic 'ZZZ4' at z, u32 output_size at z+4, LZ4 block at z+8.
"""
import argparse
import hashlib
import json
import struct
import sys

sys.path.insert(0, __file__.rsplit('/', 1)[0])


def lz4_tolerant(src, limit=1 << 22):
    """LZ4 block decoder that returns the bytes produced before any error."""
    out = bytearray()
    i = 0
    n = len(src)
    try:
        while i < n and len(out) < limit:
            tok = src[i]
            i += 1
            ll = tok >> 4
            if ll == 15:
                while True:
                    x = src[i]
                    i += 1
                    ll += x
                    if x != 255:
                        break
            if i + ll > n:
                break
            out += src[i:i + ll]
            i += ll
            if i >= n:
                break
            off = src[i] | (src[i + 1] << 8)
            i += 2
            ml = (tok & 15) + 4
            if (tok & 15) == 15:
                while True:
                    x = src[i]
                    i += 1
                    ml += x
                    if x != 255:
                        break
            if off == 0 or off > len(out):
                break
            st = len(out) - off
            for j in range(ml):
                out.append(out[st + j])
    except (IndexError, ValueError):
        pass
    return bytes(out), i


NEEDLES = [b'import ', b'def ', b'class ', b'__main__', b'print(', b'marshal',
           b'AccountManager', b'asiocore', b'asyncore', b'MImporter',
           b'# -*- coding', b'#!/usr', b'#!/bin', b'from ', b'lambda',
           b'PYTHONHASHSEED', b'globals()', b'__name__']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--target-md5")
    ap.add_argument("--target-size", type=int)
    ap.add_argument("--out")
    ap.add_argument("--max-chunks", type=int, default=0)
    a = ap.parse_args()

    data = open(a.path, "rb").read()
    print("file %s (%d bytes)" % (a.path, len(data)), file=sys.stderr)

    hits = []
    pos = 0
    nchunks = 0
    while True:
        z = data.find(b"ZZZ4", pos)
        if z < 0:
            break
        pos = z + 4
        if z + 8 > len(data):
            break
        outsz = struct.unpack_from("<I", data, z + 4)[0]
        if outsz == 0 or outsz > (1 << 26):
            continue
        payload, used = lz4_tolerant(data[z + 8:])
        if not payload:
            continue
        nchunks += 1
        md5 = hashlib.md5(payload).hexdigest()
        found = [n.decode() for n in NEEDLES if n in payload]
        size_hit = (a.target_size is not None and len(payload) == a.target_size)
        md5_hit = (a.target_md5 is not None and md5 == a.target_md5)
        if found or size_hit or md5_hit:
            rec = {"offset": z, "decoded_size": len(payload), "used": used,
                   "header_out_size": outsz, "md5": md5, "needles": found,
                   "size_hit": size_hit, "md5_hit": md5_hit}
            hits.append(rec)
            print(json.dumps(rec))
            if a.out:
                open("%s.%08x.bin" % (a.out, z), "wb").write(payload)
        if a.max_chunks and nchunks >= a.max_chunks:
            break
    print("scanned %d chunks, %d interesting" % (nchunks, len(hits)), file=sys.stderr)


if __name__ == "__main__":
    main()
