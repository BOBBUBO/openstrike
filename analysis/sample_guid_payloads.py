#!/usr/bin/env python3
"""Sample GUID-named patch records and characterise their payloads.

The encrypted Python modules live in the patch under hashed/UUID names, so
there is no name to grep for.  Instead we fingerprint payloads: look for a
recurring header ("head"/"headlen" in MImporter), zlib/gzip magic, or a
distinctive common prefix that would identify the encrypted-module container.
"""
import collections
import json
import re
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from mpk_extract import ArchiveMap, decode_entry

PATCH_DIR = 'stock-files/com.netease.newspike/files/LocalData/Patch'


def main():
    recs = [json.loads(l) for l in open('analysis/patch-records.jsonl')]
    guid = [r for r in recs if re.match(r'^[0-9a-f]{2}/[0-9a-fA-F-]{36}$', r.get('path', ''))]
    print('guid records:', len(guid))
    # sample evenly across the list plus the smallest ones
    sample = guid[::max(1, len(guid) // 400)][:400]
    sample += sorted(guid, key=lambda r: r['stored_size'])[:100]

    am = ArchiveMap(PATCH_DIR)
    prefixes = collections.Counter()
    kinds = collections.Counter()
    examples = {}
    zlibish = []
    with open(os.path.join(PATCH_DIR, 'Patch.mpk'), 'rb') as f0, \
         open(os.path.join(PATCH_DIR, 'Patch1.mpk'), 'rb') as f1, \
         open(os.path.join(PATCH_DIR, 'Patch2.mpk'), 'rb') as f2, \
         open(os.path.join(PATCH_DIR, 'Patch3.mpk'), 'rb') as f3, \
         open(os.path.join(PATCH_DIR, 'Patch4.mpk'), 'rb') as f4, \
         open(os.path.join(PATCH_DIR, 'Patch5.mpk'), 'rb') as f5, \
         open(os.path.join(PATCH_DIR, 'Patch6.mpk'), 'rb') as f6, \
         open(os.path.join(PATCH_DIR, 'Patch7.mpk'), 'rb') as f7:
        handles = {'Patch.mpk': f0, 'Patch1.mpk': f1, 'Patch2.mpk': f2,
                   'Patch3.mpk': f3, 'Patch4.mpk': f4, 'Patch5.mpk': f5,
                   'Patch6.mpk': f6, 'Patch7.mpk': f7}
        for r in sample:
            try:
                path, off = am.locate(r['archive_offset'])
            except ValueError:
                continue
            fh = handles[os.path.basename(path)]
            fh.seek(off)
            raw = fh.read(r['stored_size'])
            if len(raw) != r['stored_size']:
                continue
            try:
                payload, kind, det = decode_entry(raw)
            except Exception:
                kinds['decode-failed'] += 1
                continue
            kinds[kind] += 1
            if not payload:
                continue
            prefixes[bytes(payload[:8])] += 1
            if payload[:2] in (b'\x78\x9c', b'\x78\xda', b'\x78\x01') or \
               payload[:2] == b'\x1f\x8b':
                zlibish.append((r['path'], len(payload), payload[:2].hex()))
    print('kinds:', dict(kinds))
    print('\nmost common 8-byte prefixes:')
    for p, c in prefixes.most_common(25):
        print('  %-20s %d' % (p.hex(), c))
    print('\nzlib/gzip payloads found: %d' % len(zlibish))
    for x in zlibish[:20]:
        print('   ', x)


if __name__ == '__main__':
    main()
