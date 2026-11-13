#!/usr/bin/env python3
"""Examine the MPK wrapper framing for records that contain several chunks."""
import json
import os
import struct
import sys

sys.path.insert(0, 'analysis')
from lz4_block import decompress_with_consumed
from mpk_extract import ArchiveMap, MPK_MAGIC

PATCH_DIR = 'stock-files/com.netease.newspike/files/LocalData/Patch'


def main():
    recs = [json.loads(l) for l in open('analysis/patch-records.jsonl')]
    am = ArchiveMap(PATCH_DIR)
    handles = {os.path.basename(p): open(p, 'rb') for _, _, p in am.entries}
    shown = 0
    for r in recs:
        if r['stored_size'] < 4096:
            continue
        path, off = am.locate(r['archive_offset'])
        fh = handles[os.path.basename(path)]
        fh.seek(off)
        raw = fh.read(r['stored_size'])
        if not raw.startswith(MPK_MAGIC):
            continue
        if raw[0x38:0x3c] != b'ZZZ4':
            continue
        osize = struct.unpack_from('<I', raw, 0x3c)[0]
        try:
            out, used = decompress_with_consumed(raw[0x40:], osize)
        except Exception:
            continue
        pos = 0x40 + used
        nchunks = 1
        chunks = [(0x38, osize, used, len(out))]
        while pos + 0x40 < len(raw) and nchunks < 12:
            # what follows the previous chunk?
            print('  after chunk %d at 0x%x: %s' % (nchunks, pos, raw[pos:pos + 0x48].hex()))
            break
        print('record %s stored=%d first chunk out=%d used=%d, next pos=0x%x'
              % (r['path'], r['stored_size'], len(out), used, pos))
        if shown < 4:
            shown += 1


if __name__ == '__main__':
    main()
