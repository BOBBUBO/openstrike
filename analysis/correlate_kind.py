#!/usr/bin/env python3
"""Correlate the Patch.mpkinfo record bytes with the actual payload type.

For every record of the '=QH32sBBQ' section we seek to its global
archive_offset and look at what is really stored there.  If the payload
starts with the '.MESSIAH' magic we can compare the container's u32
type_flags against the candidate flag/kind bytes of the record and work
out the exact bit layout.
"""
import collections
import json
import os
import struct

P = 'stock-files/com.netease.newspike/files/LocalData/Patch'
MAGIC = b'.MESSIAH'

files = sorted(f for f in os.listdir(P) if f.startswith('Patch')
               and f.endswith('.mpk'))
sizes = {f: os.path.getsize(os.path.join(P, f)) for f in files}
base = {}
off = 0
for f in files:
    base[f] = off
    off += sizes[f]
print('archives:', [(f, sizes[f]) for f in files])
print('total:', off)

fh = {}
def read_at(g, n):
    for f in files:
        if base[f] <= g < base[f] + sizes[f]:
            h = fh.get(f)
            if h is None:
                h = fh[f] = open(os.path.join(P, f), 'rb')
            h.seek(g - base[f])
            return h.read(n), f
    return None, None

recs = [json.loads(l) for l in open('analysis/patch-kind-records.jsonl')]
hist = collections.Counter()
cor = collections.Counter()
examples = []
for r in recs:
    g = r['aoff']
    blob, fn = read_at(g, 24)
    if blob is None:
        hist['oob'] += 1
        continue
    if blob[:8] == MAGIC:
        tf = struct.unpack_from('<I', blob, 8)[0]
        hist['messiah'] += 1
        cor[(r['kind'], tf & 0xffff, tf >> 16)] += 1
        if len(examples) < 8:
            examples.append((r['name'], r['flags'], r['kind'], fn, g,
                             hex(tf), blob[12:28].hex()))
    else:
        hist[blob[:4].hex() + ('+messiah' if MAGIC in blob[:24] else '')] += 1

print('\npayload magic histogram:')
for k, v in hist.most_common(20):
    print('   %-28s %d' % (k, v))
print('\n(record.kind, messiah_type, messiah_flags) correlation:')
for k, v in cor.most_common(30):
    print('   kind=%-4d type=%-4d flags=0x%05x  %d' % (k[0], k[1], k[2], v))
print('\nexamples:')
for e in examples:
    print('   %-55s recflags=%-4d reckind=%-4d %s@%d tf=%s body=%s' % e)
