#!/usr/bin/env python3
"""Dump and characterise the ``.MESSIAH`` container records found in the patch."""
import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
from mpk_extract import ArchiveMap

PATCH_DIR = 'stock-files/com.netease.newspike/files/LocalData/Patch'


def main():
    hits = json.load(open('analysis/messiah-magic-records.json'))
    # de-duplicate by (path, archive_offset)
    uniq = {}
    for r in hits:
        uniq[(r['path'], r['archive_offset'])] = r
    rows = list(uniq.values())
    print('unique .MESSIAH entries:', len(rows))
    sizes = collections.Counter(r['stored_size'] for r in rows)
    print('size histogram (top 20):', sizes.most_common(20))
    am = ArchiveMap(PATCH_DIR)
    handles = {}
    for _, _, p in am.entries:
        handles[os.path.basename(p)] = open(p, 'rb')
    os.makedirs('analysis/messiah-records', exist_ok=True)
    shown = 0
    for r in rows:
        path, off = am.locate(r['archive_offset'])
        fh = handles[os.path.basename(path)]
        fh.seek(off)
        data = fh.read(r['stored_size'])
        if len(data) < 8 or not data.startswith(b'.MESSIAH'):
            continue
        out = os.path.join('analysis/messiah-records',
                           r['path'].replace('/', '_'))
        with open(out, 'wb') as f:
            f.write(data)
        if shown < 8:
            print('\n--- %s  (%d bytes)' % (r['path'], len(data)))
            print('    ', data[:96].hex())
            print('    ascii:', repr(data[:96]))
            shown += 1
    print('\nwrote %d files to analysis/messiah-records/' % len(rows))


if __name__ == '__main__':
    main()
