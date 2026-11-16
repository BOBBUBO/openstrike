#!/usr/bin/env python3
"""
Scan every package file payload (with the CORRECTED container/offset mapping
from analysis/rebuild_file_table.py) for Python source, bytecode, zlib/gzip
streams, or marshal data.

This supersedes the earlier scans (analysis/scan_encrypted_modules.py and
analysis/find_encrypted_modules.py) which used the WRONG container assignment
and therefore read garbage bytes for every flags==0 record.
"""
import collections
import json
import os
import re
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ASSETS = os.path.join(ROOT, 'decompiled/apk/split_base_mpk/assets')

PY_TOKENS = (b'import ', b'def ', b'class ', b'print(', b'__name__',
             b'self.', b'lambda ', b'None', b'True', b'return ', b'elif ',
             b'from ', b'global ', b'assert ', b'yield ', b'with ',
             b'except ', b'raise ', b'async ', b'await ')
PY_MAGIC = (b'\xcb\x0d\x0d\x0a', b'\x6f\x0d\x0d\x0a', b'\xa7\x0d\x0d\x0a',
            b'\x55\x0d\x0d\x0a')          # CPython 3.x / 3.12 pyc magics
MARSHAL_TAG = 0x63                       # TYPE_CODE 'c'

NEEDLES = (b'import ', b'def ', b'class ', b'print(', b'__name__',
           b'from .', b'from _', b'# -*- coding', b'"""')


def main():
    rows = [json.loads(l) for l in open(os.path.join(HERE, 'package-file-table2.jsonl'))]
    f0 = open(os.path.join(ASSETS, 'Resources.mpk'), 'rb')
    f1 = open(os.path.join(ASSETS, 'Resources1.mpk'), 'rb')
    fh = {'Resources.mpk': f0, 'Resources1.mpk': f1}

    stats = collections.Counter()
    hits = []
    by_ext = collections.Counter()
    for r in rows:
        cont = r.get('container')
        if not cont or not r.get('name'):
            continue
        f = fh[cont]
        f.seek(r['offset'])
        body = f.read(r['size'])
        if len(body) != r['size']:
            stats['short_read'] += 1
            continue
        name = r['name']
        ext = name.rsplit('.', 1)[-1] if '.' in name.rsplit('/', 1)[-1] else ''
        by_ext[ext] += 1

        # 1) raw python source
        nt = sum(1 for t in NEEDLES if t in body)
        if nt >= 3:
            stats['python_source'] += 1
            hits.append(('source', name, r['size'], nt))
            continue
        # 2) pyc magic
        if body[:4] in PY_MAGIC:
            stats['pyc_magic'] += 1
            hits.append(('pyc', name, r['size'], body[:4].hex()))
            continue
        # 3) marshal code object
        if body[:1] == b'c' and len(body) > 8 and body[1:2] in b'\x00\x01\x02\x03':
            stats['marshal_code'] += 1
            hits.append(('marshal', name, r['size'], body[:8].hex()))
            continue
        # 4) zlib stream somewhere in the first 4096 bytes
        for off in range(0, min(len(body), 4096)):
            if body[off:off + 1] != b'\x78':
                continue
            for wb in (15, -15, 31):
                try:
                    d = zlib.decompress(body[off:], wb)
                except Exception:
                    continue
                if len(d) < 16:
                    continue
                py = sum(1 for t in PY_TOKENS if t in d)
                stats['zlib_ok'] += 1
                if py >= 3 or d[:4] in PY_MAGIC or d[:1] == b'c':
                    stats['zlib_python'] += 1
                    hits.append(('zlib_python', name, r['size'], off))
                break
            break

    print('scanned:', stats['python_source'] + stats['pyc_magic'] +
          stats['marshal_code'] + stats['zlib_ok'] + stats['short_read'])
    for k, v in stats.most_common():
        print('  %-18s %d' % (k, v))
    print('--- top extensions ---')
    print(by_ext.most_common(25))
    print('--- hits (%d) ---' % len(hits))
    for h in hits[:60]:
        print('  ', h)
    json.dump(hits, open(os.path.join(HERE, 'package-python-hits.json'), 'w'), indent=1)


if __name__ == '__main__':
    main()
