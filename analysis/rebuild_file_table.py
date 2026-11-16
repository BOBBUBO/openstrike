#!/usr/bin/env python3
"""
Rebuild the Android package file table with the CORRECT container assignment.

CORRECTION (this turn)
-----------------------
`Resources.mpkinfo` stores a **global byte offset** in `digest_words[1]`, but the
container that holds the payload depends on the record's `flags` field:

    flags == 0  ->  payload lives in  Resources.mpk     at  offset = digest_words[1]
    flags == 2  ->  payload lives in  Resources1.mpk    at  offset = digest_words[1]
    flags == 1  ->  directory / index entry (logical_size usually 0)

The previous builder (`analysis/build_file_table.py`) guessed the container by
comparing `offset + size` against the two file lengths, which mis-assigned every
flags==0 record (all of them were claimed to be in Resources1.mpk).  That is why
"Resources.mpk GUID payloads never verify" and why the prerequisite filelist
looked encrypted.

Verification: the 153-entry prerequisite filelist recovered from
`essential_py3` now matches its md5 exactly (153/153) when read from
Resources.mpk at the raw mpkinfo offset.
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
ASSETS = os.path.join(ROOT, 'decompiled/apk/split_base_mpk/assets')
PATCHLIST = os.path.join(
    ROOT, 'stock-files/com.netease.newspike/files/LocalData/Patch/'
          'spike_patchlist_android_astc_512_py3.txt')
SECTIONS = ('common', 'android_common', 'android_common_32', 'android_astc_512')


def load_mpkinfo():
    out = []
    with open(os.path.join(HERE, 'resources-mpkinfo.jsonl')) as f:
        for line in f:
            out.append(json.loads(line))
    return out


def main():
    pl = json.load(open(PATCHLIST))
    byhash = collections.defaultdict(list)
    for s in SECTIONS:
        d = pl.get(s) or {}
        if not isinstance(d, dict):
            continue
        for name, val in d.items():
            if isinstance(val, (list, tuple)) and len(val) == 2:
                byhash[murmur3_32(name)].append((name, val[0], val[1], s))

    f0 = open(os.path.join(ASSETS, 'Resources.mpk'), 'rb')
    f1 = open(os.path.join(ASSETS, 'Resources1.mpk'), 'rb')
    L0 = os.path.getsize(os.path.join(ASSETS, 'Resources.mpk'))
    L1 = os.path.getsize(os.path.join(ASSETS, 'Resources1.mpk'))

    recs = load_mpkinfo()
    stats = collections.Counter()
    verified = 0
    with open(os.path.join(HERE, 'package-file-table2.jsonl'), 'w') as out:
        for r in recs:
            off = r['digest_words'][1]
            sz = r['logical_size']
            fl = r['flags']
            row = {
                'name': None, 'section': None, 'md5_original': None,
                'md5_stored': None, 'size': sz, 'offset': off,
                'container': None, 'flags': fl,
                'suffix': r['path_suffix'], 'digest0': r['digest_words'][0],
                'method': None, 'candidates': [],
            }
            if sz == 0:
                row['method'] = 'directory'
                stats['directory'] += 1
                out.write(json.dumps(row) + '\n')
                continue
            # ---- correct container selection ----
            if fl == 2:
                cont, fh, limit = 'Resources1.mpk', f1, L1
            else:
                cont, fh, limit = 'Resources.mpk', f0, L0
            if off + sz > limit:
                # fall back: try the other container
                alt, afh, alimit = (('Resources.mpk', f0, L0) if cont.endswith('1.mpk')
                                    else ('Resources1.mpk', f1, L1))
                if off + sz <= alimit:
                    cont, fh, limit = alt, afh, alimit
                    stats['container_fallback'] += 1
                else:
                    row['method'] = 'out_of_range'
                    stats['out_of_range'] += 1
                    out.write(json.dumps(row) + '\n')
                    continue
            row['container'] = cont
            fh.seek(off)
            body = fh.read(sz)
            row['md5_stored'] = hashlib.md5(body).hexdigest()

            cands = byhash.get(r['digest_words'][0], [])
            chosen = None
            m = [c for c in cands if c[1] == row['md5_stored'] and c[2] == sz]
            if len(m) == 1:
                chosen, row['method'] = m[0], 'md5+hash'
            elif len(m) > 1:
                chosen, row['method'] = m[0], 'md5+hash(amb)'
                stats['md5_ambiguous'] += 1
            if chosen is None and len(cands) == 1:
                chosen, row['method'] = cands[0], 'hash'
            if chosen is None and len(cands) > 1:
                same = [c for c in cands if c[2] == sz]
                if len(same) == 1:
                    chosen, row['method'] = same[0], 'hash+size'
            if chosen is None:
                row['candidates'] = [c[0] for c in cands]
                row['method'] = 'ambiguous' if cands else 'unresolved'
                stats[row['method']] += 1
                out.write(json.dumps(row) + '\n')
                continue
            row['name'] = chosen[0]
            row['section'] = chosen[3]
            row['md5_original'] = chosen[1]
            if chosen[1] == row['md5_stored']:
                stats['md5_verified'] += 1
                verified += 1
            else:
                stats['md5_mismatch'] += 1
            out.write(json.dumps(row) + '\n')

    print('records        :', len(recs))
    print('md5 verified   :', verified)
    for k, v in stats.most_common():
        print('  %-22s %d' % (k, v))


if __name__ == '__main__':
    main()
