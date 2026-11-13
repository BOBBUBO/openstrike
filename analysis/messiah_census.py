#!/usr/bin/env python3
"""Full census of .MESSIAH containers in the raw patch archives.

Earlier passes only decoded 927 unique records.  A raw byte scan shows the
literal ".MESSIAH" occurs ~2,700 times in EVERY Patch*.mpk, i.e. ~19k in
total.  This script enumerates every occurrence, reads the u32 kind that
follows the 8-byte magic, and records the surrounding bytes so that the
container layout can be re-derived.
"""
import collections
import hashlib
import json
import os
import sys

PATCH = 'stock-files/com.netease.newspike/files/LocalData/Patch'
MAGIC = b'.MESSIAH'
OUT = 'analysis/messiah-census.json'


def main():
    files = sorted(f for f in os.listdir(PATCH) if f.startswith('Patch')
                   and f.endswith('.mpk'))
    kinds = collections.Counter()
    recs = []
    per_file = {}
    for fn in files:
        p = os.path.join(PATCH, fn)
        d = open(p, 'rb').read()
        pos = 0
        n = 0
        while True:
            i = d.find(MAGIC, pos)
            if i < 0:
                break
            pos = i + 1
            n += 1
            if i + 12 > len(d):
                continue
            kind = int.from_bytes(d[i + 8:i + 12], 'little')
            kinds[kind] += 1
            recs.append({
                'file': fn, 'offset': i, 'kind': kind,
                'after': d[i + 12:i + 12 + 32].hex(),
                'before': d[max(0, i - 32):i].hex(),
            })
        per_file[fn] = n
        print('%-12s %d .MESSIAH markers' % (fn, n))
    print('\ntotal markers: %d' % len(recs))
    print('kind histogram:')
    for k, v in sorted(kinds.items()):
        print('   kind %-10d %d' % (k, v))
    # what follows each kind?
    print('\n--- sample ' + 'first 6 bytes after magic+kind, by kind ---')
    seen = {}
    for r in recs:
        k = r['kind']
        seen.setdefault(k, []).append(r)
    for k, rs in sorted(seen.items()):
        print('kind %d  (%d records)' % (k, len(rs)))
        for r in rs[:3]:
            print('    %s@%d  after=%s' % (r['file'], r['offset'],
                                           r['after'][:32]))
    json.dump({'per_file': per_file, 'kinds': dict(kinds),
               'records': recs}, open(OUT, 'w'))
    print('\nwrote %s (%d records)' % (OUT, len(recs)))


if __name__ == '__main__':
    main()
