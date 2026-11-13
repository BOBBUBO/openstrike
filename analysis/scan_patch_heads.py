#!/usr/bin/env python3
"""Empirical scan of the patch archives for encrypted Python module files.

MImporter's recovered algorithm is

    raw  = open_file_data_in_package/patch(encrypted_name)
    head, sdata = raw[:headlen], raw[headlen:]
    key  = gen_md5(salt)
    cdata = xor/rotate-decrypt(sdata, key)
    code = marshal.loads(zlib.decompress(cdata))

so an encrypted module is a short *head* (which carries headlen and probably
the salt) followed by high-entropy payload.  This script reads the first 96
bytes of every indexed patch record and looks for that shape:
  * a plausible headlen stored as a u16/u32 near the start, and
  * the remaining bytes being high entropy.
It also reports the most common magic prefixes so we can spot a family.
"""
import collections
import json
import math
import os
import struct

PATCHDIR = 'stock-files/com.netease.newspike/files/LocalData/Patch'
RECS = 'analysis/patch-records.jsonl'
MAGICS = {}


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main():
    files = {}
    heads = collections.Counter()
    hits = []
    nrec = 0
    with open(RECS) as f:
        for line in f:
            try:
                r = json.loads(line)
            except Exception:
                continue
            path = r.get('archive')
            aoff = r.get('archive_offset')
            size = r.get('stored_size')
            if not path or aoff is None or not size:
                continue
            fh = files.get(path)
            if fh is None:
                if not os.path.exists(path):
                    continue
                fh = open(path, 'rb')
                files[path] = fh
            nrec += 1
            try:
                fh.seek(aoff)
                head = fh.read(min(96, size))
            except Exception:
                continue
            if len(head) < 24:
                continue
            heads[head[:4]] += 1
            # candidate headlen: u16/u32 at offsets 0,2,4,8,12
            hl = None
            for off, fmt in ((0, '<H'), (2, '<H'), (4, '<I'), (8, '<I'),
                             (12, '<I'), (16, '<I'), (4, '<H'), (8, '<H')):
                try:
                    v = struct.unpack_from(fmt, head, off)[0]
                except Exception:
                    continue
                if 4 <= v <= 64 and v + 8 <= len(head):
                    hl = (off, fmt, v)
                    break
            if hl:
                payload = head[hl[2]:hl[2] + 32]
                if len(payload) >= 16 and entropy(payload) > 4.0:
                    hits.append((r.get('path'), hl, head[:24].hex(),
                                 round(entropy(payload), 2), size))

    print('records read:', nrec)
    print('\nmost common 4-byte prefixes:')
    for m, c in heads.most_common(25):
        print('   %s  x%d' % (m.hex(), c))
    print('\ncandidates with a plausible embedded headlen: %d' % len(hits))
    for h in hits[:40]:
        print('   %-52s hl@%d%s=%-3d head=%s ent=%s size=%d'
              % (str(h[0])[:52], h[1][0], h[1][1][-1], h[1][2], h[2][:24], h[3], h[4]))


if __name__ == '__main__':
    main()
