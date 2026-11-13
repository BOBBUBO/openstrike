#!/usr/bin/env python3
"""Scan a file for zlib/deflate streams and report what they inflate to.

MImporter decrypts a module and then calls ``zlib.decompress`` on it, so any
embedded Python source is very likely stored as (encrypted) zlib data.  We
therefore look for every plausible zlib stream start and try to inflate it.
"""
import argparse
import os
import re
import zlib


def scan(path, max_out=8 << 20, limit=40):
    data = open(path, 'rb').read()
    hits = []
    for m in re.finditer(rb'\x78[\x01\x5e\x9c\xda]', data):
        off = m.start()
        try:
            d = zlib.decompressobj()
            out = d.decompress(data[off:off + max_out], max_out)
            if len(out) < 32:
                continue
            consumed = len(data[off:]) - len(d.unused_data)
            hits.append((off, len(out), consumed, out[:64]))
        except zlib.error:
            continue
        if len(hits) >= limit:
            break
    return len(data), hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--max-out', type=int, default=8 << 20)
    ap.add_argument('--limit', type=int, default=40)
    args = ap.parse_args()
    for p in args.paths:
        size, hits = scan(p, args.max_out, args.limit)
        print('== %s (%d bytes): %d zlib streams' % (p, size, len(hits)))
        for off, olen, consumed, head in hits:
            printable = sum(1 for c in head if 32 <= c < 127 or c in (9, 10, 13))
            print('   off=0x%-9x out=%-9d consumed=%-9d printable=%d/%d %r'
                  % (off, olen, consumed, printable, len(head), head[:48]))


if __name__ == '__main__':
    main()
