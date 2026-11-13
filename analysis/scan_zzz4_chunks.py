#!/usr/bin/env python3
"""Fast sweep of every ZZZ4 (LZ4-block) chunk in an mpk/package.

Uses liblz4 through ctypes (the pure-python decoder is far too slow for a
200 MB package).

Framing (identical on the patch and the package side):
    'ZZZ4' at z | u32 output_size at z+4 | LZ4 block at z+8
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import json
import struct
import sys


def load_lz4():
    for cand in ("liblz4.so.1", "liblz4.so"):
        try:
            lib = ctypes.CDLL(cand)
            break
        except OSError:
            lib = None
    if lib is None:
        raise SystemExit("liblz4 not found")
    lib.LZ4_decompress_safe.restype = ctypes.c_int
    lib.LZ4_decompress_safe.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_int, ctypes.c_int]
    # The engine's LZ4 blocks violate liblz4's "safe" end-of-block rules, so
    # LZ4_decompress_safe returns a negative error even though it wrote the
    # right bytes.  LZ4_decompress_safe_partial (decode exactly N output
    # bytes) works and is also an order of magnitude faster than python.
    lib.LZ4_decompress_safe_partial.restype = ctypes.c_int
    lib.LZ4_decompress_safe_partial.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                                ctypes.c_int, ctypes.c_int,
                                                ctypes.c_int]
    lib.LZ4_versionNumber.restype = ctypes.c_int
    return lib


NEEDLES = [b'import ', b'def ', b'class ', b'__main__', b'print(', b'marshal',
           b'AccountManager', b'asiocore', b'asyncore', b'MImporter',
           b'# -*- coding', b'#!/usr', b'#!/bin', b'from ', b'lambda',
           b'__name__', b'#!']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--target-md5")
    ap.add_argument("--target-size", type=int)
    ap.add_argument("--size-min", type=int, default=0)
    ap.add_argument("--size-max", type=int, default=1 << 24)
    ap.add_argument("--out")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    lib = load_lz4()
    data = open(a.path, "rb").read()
    n = len(data)
    buf = (ctypes.c_char * n).from_buffer_copy(data)
    dst = ctypes.create_string_buffer(1 << 24)

    pos = 0
    chunks = 0
    hits = 0
    while True:
        z = data.find(b"ZZZ4", pos)
        if z < 0:
            break
        pos = z + 4
        if z + 8 > n:
            break
        outsz = struct.unpack_from("<I", data, z + 4)[0]
        if outsz < a.size_min or outsz > a.size_max or outsz == 0:
            continue
        r = lib.LZ4_decompress_safe_partial(
            ctypes.byref(buf, z + 8), dst, ctypes.c_int(n - z - 8),
            ctypes.c_int(outsz), ctypes.c_int(outsz + 64))
        if r != outsz:
            continue
        chunks += 1
        payload = dst.raw[:r]
        md5 = hashlib.md5(payload).hexdigest()
        found = [x.decode() for x in NEEDLES if x in payload]
        size_hit = (a.target_size is not None and r == a.target_size)
        md5_hit = (a.target_md5 is not None and md5 == a.target_md5)
        if found or size_hit or md5_hit:
            hits += 1
            rec = {"offset": z, "size": r, "md5": md5, "needles": found,
                   "size_hit": size_hit, "md5_hit": md5_hit}
            print(json.dumps(rec))
            sys.stdout.flush()
            if a.out:
                open("%s.%08x.bin" % (a.out, z), "wb").write(payload)
        elif not a.quiet and chunks % 2000 == 0:
            print("... %d chunks" % chunks, file=sys.stderr)
    print("decoded %d chunks, %d hits" % (chunks, hits), file=sys.stderr)


if __name__ == "__main__":
    main()
