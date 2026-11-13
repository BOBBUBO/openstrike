#!/usr/bin/env python3
"""Find MChecker '=QH32sBBQ' records in Patch.mpkinfo with strict validation.

  stored_size:u64 | name_len:u16 | name | md5:32B(binary) | flags:u8 |
  kind:u8 | archive_offset:u64 | (logical_size:u32 ...)

The 'kind' byte tells us the payload encoding of the asset inside the patch
archive.  We only accept records whose name is a believable asset path
(contains '/', sane extension) so that random byte matches do not pollute
the histogram.
"""
import collections
import os
import re
import struct

PATCHDIR = 'stock-files/com.netease.newspike/files/LocalData/Patch'
ARCHIVES = ['Patch.mpk', 'Patch1.mpk', 'Patch2.mpk', 'Patch3.mpk',
            'Patch4.mpk', 'Patch5.mpk', 'Patch6.mpk', 'Patch7.mpk']
total = 0
for a in ARCHIVES:
    p = os.path.join(PATCHDIR, a)
    if os.path.exists(p):
        total += os.path.getsize(p)

PATH_RE = re.compile(rb'^[A-Za-z0-9_./+\- ]+\.[A-Za-z0-9_]{1,8}$')
UUID_RE = re.compile(rb'^[0-9a-f]{2}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
                     rb'[0-9a-f]{4}-[0-9a-f]{12}(\.\d+)?$')

data = open(os.path.join(PATCHDIR, 'Patch.mpkinfo'), 'rb').read()
n = len(data)
print('Patch.mpkinfo %d bytes, archive space %d' % (n, total))

hits = []
off = 0
while off + 52 <= n:
    stored, nlen = struct.unpack_from('<QH', data, off)
    if 0 < stored < 200_000_000 and 3 <= nlen <= 300 and off + 52 + nlen <= n:
        name = data[off + 10:off + 10 + nlen]
        if PATH_RE.match(name) or UUID_RE.match(name):
            p = off + 10 + nlen
            md5 = data[p:p + 32]
            flags = data[p + 32]
            kind = data[p + 33]
            aoff = struct.unpack_from('<Q', data, p + 34)[0]
            if aoff < total:
                hits.append(dict(off=off, stored=stored, name=name.decode('ascii'),
                                 md5=md5.hex(), flags=flags, kind=kind, aoff=aoff))
                off = p + 42
                continue
    off += 1

print('validated records:', len(hits))
kinds = collections.Counter(h['kind'] for h in hits)
print('\nkind histogram:')
for k, c in kinds.most_common(40):
    ex = next(h for h in hits if h['kind'] == k)
    print('  kind=%-4d x%-6d flags=%-4d  %s' % (k, c, ex['flags'], ex['name'][:64]))

import json
with open('analysis/patch-kind-records.jsonl', 'w') as f:
    for h in hits:
        f.write(json.dumps(h) + '\n')
print('\nwrote analysis/patch-kind-records.jsonl')
