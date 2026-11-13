#!/usr/bin/env python3
"""Parse the ``.MESSIAH`` container format found in the Patch*.mpk archives.

Layout (little endian):
  0x00  char magic[8]   ".MESSIAH"
  0x08  u32   kind      1 = blob + name, 2 = name table
  0x0C  u32   length    size of the body that follows
  0x10  body

kind 2 body: repeated (u16 name_len, char name[name_len])
kind 1 body: compressed/encoded blob followed by a trailing name string
"""
import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
from mpk_extract import ArchiveMap

PATCH_DIR = 'stock-files/com.netease.newspike/files/LocalData/Patch'
MAGIC = b'.MESSIAH'


def parse(data):
    if not data.startswith(MAGIC):
        raise ValueError('bad magic')
    kind, length = struct.unpack_from('<II', data, 8)
    body = data[16:16 + length]
    return kind, length, body


def parse_names(body):
    names = []
    i = 0
    while i + 2 <= len(body):
        n = struct.unpack_from('<H', body, i)[0]
        i += 2
        if n == 0:
            continue
        if i + n > len(body):
            break
        names.append(body[i:i + n].decode('utf-8', 'replace'))
        i += n
    return names


def main():
    hits = json.load(open('analysis/messiah-magic-records.json'))
    uniq = {}
    for r in hits:
        uniq[(r['path'], r['archive_offset'])] = r
    rows = list(uniq.values())
    am = ArchiveMap(PATCH_DIR)
    handles = {os.path.basename(p): open(p, 'rb') for _, _, p in am.entries}

    kinds = collections.Counter()
    name_counter = collections.Counter()
    out = []
    for r in rows:
        path, off = am.locate(r['archive_offset'])
        fh = handles[os.path.basename(path)]
        fh.seek(off)
        data = fh.read(r['stored_size'])
        if not data.startswith(MAGIC):
            continue
        try:
            kind, length, body = parse(data)
        except Exception:
            continue
        kinds[kind] += 1
        rec = {'path': r['path'], 'kind': kind, 'length': length,
               'stored_size': r['stored_size'], 'archive_offset': r['archive_offset']}
        if kind == 2:
            names = parse_names(body)
            rec['names'] = names
            for n in names:
                name_counter[n] += 1
        else:
            # find the trailing NUL-terminated name
            tail = body
            name = ''
            for j in range(len(tail) - 1, max(-1, len(tail) - 80), -1):
                if tail[j] == 0:
                    seg = tail[j + 1:]
                    if seg and all(32 <= c < 127 for c in seg):
                        name = seg.decode()
                        body = tail[:j + 1]
                    break
            rec['name'] = name
            rec['blob_len'] = len(body)
            rec['blob_head'] = body[:16].hex()
            if name:
                name_counter[name] += 1
        out.append(rec)
    json.dump(out, open('analysis/messiah-records.json', 'w'), indent=1)
    print('kinds:', dict(kinds))
    print('\nmost common names (%d distinct):' % len(name_counter))
    for n, c in name_counter.most_common(60):
        print('  %-60s %d' % (n, c))
    print('\nname samples that look like python/script:')
    for n in sorted(name_counter):
        if any(k in n.lower() for k in ('.py', 'script', 'python', 'import',
                                        'async', 'gate', 'client', 'logic')):
            print('   ', n, name_counter[n])


if __name__ == '__main__':
    main()
