#!/usr/bin/env python3
"""Definitive Blood Strike Android package file table.

Sources
  * Resources.mpkinfo  (decompiled/apk/split_base_mpk/assets/Resources.mpkinfo)
      -> 45,489 records of 20 bytes:
             u8 kind | u8 name_suffix[3] | u32 digest0 | u32 digest1 | u32 size | u32 flags
         digest0 = MurmurHash3_x86_32(name, seed 0)   <- CRACKED
         digest1 = global byte offset of the file body
  * spike_patchlist_android_astc_512_py3.txt
      -> name -> [original md5, size] per section
         (common / android_common / android_common_32 / android_astc_512)

Output: analysis/package-file-table.jsonl   one line per mpkinfo record
        analysis/package-file-table-summary.json
"""
import json, sys, hashlib, collections, os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from package_index import load_mpkinfo, PKG
from murmur3 import murmur3_32

PATCHLIST = ('stock-files/com.netease.newspike/files/LocalData/Patch/'
             'spike_patchlist_android_astc_512_py3.txt')
R0 = 'decompiled/apk/split_base_mpk/assets/Resources.mpk'
R1 = 'decompiled/apk/split_base_mpk/assets/Resources1.mpk'
SECTIONS = ['common', 'android_common', 'android_common_32', 'android_astc_512']


def J(v):
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, dict):
        return {J(k): J(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [J(x) for x in v]
    return v


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

    d0 = open(R0, 'rb').read()
    d1 = open(R1, 'rb').read()
    recs = load_mpkinfo()
    stats = collections.Counter()
    amb_hist = collections.Counter()
    seen_names = set()
    unresolved_rows = []

    with open('analysis/package-file-table.jsonl', 'w') as out:
        for r in recs:
            o = r['offset']; sz = r['size']
            row = {'name': None, 'section': None, 'md5_original': None,
                   'md5_stored': None, 'size': sz, 'offset': o,
                   'container': None, 'flags': J(r['flags']),
                   'suffix': J(r['suffix']), 'digest0': J(r['digest0']),
                   'method': None, 'candidates': []}
            if sz == 0:
                stats['directory'] += 1
                row['method'] = 'directory'
                out.write(json.dumps(row) + '\n')
                continue
            if o + sz <= len(d1):
                body = d1[o:o + sz]; row['container'] = 'Resources1.mpk'
            elif o + sz <= len(d0):
                body = d0[o:o + sz]; row['container'] = 'Resources.mpk'
            else:
                stats['out_of_range'] += 1
                row['method'] = 'out_of_range'
                out.write(json.dumps(row) + '\n')
                continue
            row['md5_stored'] = hashlib.md5(body).hexdigest()

            cands = byhash.get(r['digest0'], [])
            chosen = None
            # 1) exact md5+size
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
                if cands:
                    stats['ambiguous'] += 1
                    amb_hist[min(len(cands), 32)] += 1
                    row['method'] = 'ambiguous'
                else:
                    stats['unresolved'] += 1
                    row['method'] = 'unresolved'
                    unresolved_rows.append(row)
                out.write(json.dumps(row) + '\n')
                continue
            name, orig_md5, osz, sec = chosen
            row.update({'name': name, 'section': sec, 'md5_original': orig_md5})
            seen_names.add(name)
            stats['named_' + row['method'].replace('+', '_')] += 1
            out.write(json.dumps(row) + '\n')

    summary = {
        'mpkinfo_records': len(recs),
        'resolution': dict(stats),
        'named_total': len(seen_names),
        'unique_names': len(seen_names),
        'ambiguity_histogram': {str(k): v for k, v in sorted(amb_hist.items())},
        'hash': 'MurmurHash3_x86_32(name, seed=0)',
    }
    json.dump(summary, open('analysis/package-file-table-summary.json', 'w'), indent=2)
    with open('analysis/package-file-table-unresolved.jsonl', 'w') as f:
        for r in unresolved_rows:
            f.write(json.dumps(r) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
