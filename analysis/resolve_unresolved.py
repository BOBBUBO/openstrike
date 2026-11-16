#!/usr/bin/env python3
"""Resolve the 445 `unresolved` rows of package-file-table2.jsonl.

Those rows are mpkinfo records whose *name* could not be recovered from the
murmur3(name) bucket.  Every one of them still has a verified `md5_stored` and
`size`, so we can look the content up in the authoritative patchlist
(`spike_patchlist_android_astc_512_py3.txt`) by md5+size and recover the
logical name.
"""
import collections
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from murmur3 import murmur3_32  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PATCHLIST = os.path.join(
    ROOT, 'stock-files/com.netease.newspike/files/LocalData/Patch/'
          'spike_patchlist_android_astc_512_py3.txt')
TABLE = os.path.join(HERE, 'package-file-table2.jsonl')
PACKMAN = os.path.join(HERE, 'pack-manifest.json')
SECTIONS = ('common', 'android_common', 'android_common_32', 'android_astc_512')


def main():
    pl = json.load(open(PATCHLIST))
    by_md5 = collections.defaultdict(list)
    for s in SECTIONS:
        d = pl.get(s) or {}
        for name, val in d.items():
            if isinstance(val, (list, tuple)) and len(val) == 2:
                by_md5[(val[0].lower(), val[1])].append((name, s))

    pm = json.load(open(PACKMAN))
    pm_by_md5 = collections.defaultdict(list)
    for s, d in pm.items():
        if not isinstance(d, dict):
            continue
        for name, val in d.items():
            if isinstance(val, (list, tuple)) and len(val) == 2:
                pm_by_md5[(val[0].lower(), val[1])].append((name, s))

    rows = [json.loads(l) for l in open(TABLE)]
    fixed = 0
    still = []
    with open(os.path.join(HERE, 'package-file-table3.jsonl'), 'w') as out:
        for r in rows:
            if r.get('method') != 'unresolved':
                out.write(json.dumps(r) + '\n')
                continue
            key = (r['md5_stored'], r['size'])
            cands = by_md5.get(key, []) + pm_by_md5.get(key, [])
            names = {c[0] for c in cands}
            if len(names) == 1:
                nm = next(iter(names))
                sec = next(c[1] for c in cands if c[0] == nm)
                r['name'] = nm
                r['section'] = sec
                r['md5_original'] = r['md5_stored']
                r['method'] = 'md5+size'
                fixed += 1
            else:
                still.append(r)
            out.write(json.dumps(r) + '\n')
    print('unresolved rows      :', sum(1 for r in rows
                                        if r.get('method') == 'unresolved'))
    print('resolved by md5+size :', fixed)
    print('still unresolved     :', len(still))
    print('candidate-count histogram:',
          collections.Counter(len({c[0] for c in
                                   (by_md5.get((r['md5_stored'], r['size']), []) +
                                    pm_by_md5.get((r['md5_stored'], r['size']), []))
                                   }) for r in still).most_common(8))


if __name__ == '__main__':
    main()
