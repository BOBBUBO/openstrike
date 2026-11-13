#!/usr/bin/env python3
"""Find every patch record whose payload starts with the engine magic
``.MESSIAH`` (and report other notable magics) by reading only the first
bytes of each indexed entry.
"""
import collections
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
from mpk_extract import ArchiveMap, decode_entry

PATCH_DIR = 'stock-files/com.netease.newspike/files/LocalData/Patch'
MAGICS = [b'.MESSIAH', b'ZZZ4', b'NNNN', b'PK\x03\x04', b'\x1f\x8b', b'RIFF',
          b'\x89PNG', b'\xff\xd8\xff', b'BKHD', b'<?xml', b'{', b'[', b'\x00asm',
          b'\xcb\x0c\x0d\x0a', b'\xe3', b'\x63']


def main():
    recs = [json.loads(l) for l in open('analysis/patch-records.jsonl')]
    guid = [r for r in recs if re.match(r'^[0-9a-f]{2}/[0-9a-fA-F-]{36}$',
                                         r.get('path', ''))]
    print('guid records:', len(guid))
    am = ArchiveMap(PATCH_DIR)
    handles = {}
    for _, _, p in am.entries:
        handles[os.path.basename(p)] = open(p, 'rb')
    counts = collections.Counter()
    hits = []
    for r in guid:
        path, off = am.locate(r['archive_offset'])
        fh = handles[os.path.basename(path)]
        fh.seek(off)
        head = fh.read(16)
        if len(head) < 8:
            continue
        for m in MAGICS:
            if head.startswith(m):
                counts[m] += 1
                if m == b'.MESSIAH':
                    hits.append(r)
                break
    print('magic counts over first 16 bytes:')
    for m, c in counts.most_common():
        print('   %-14r %d' % (m, c))
    print('\n.MESSIAH records: %d' % len(hits))
    for r in hits[:40]:
        print('   ', r['path'], r['stored_size'], 'off=%d' % r['archive_offset'])
    json.dump(hits, open('analysis/messiah-magic-records.json', 'w'), indent=1)
    print('\nwrote analysis/messiah-magic-records.json')


if __name__ == '__main__':
    main()
