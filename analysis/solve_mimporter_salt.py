#!/usr/bin/env python3
"""Solve for MImporter's XOR salt.

gen_md5(name) = int.from_bytes(md5(name)[slice]) ^ salt_int   (64-bit)
The encrypted package filename is that value rendered as a UUID.

Given (logical_name -> guid) pairs we can compute salt candidates for every
plausible (digest-slice, endianness, guid-rendering) combination and keep the
one that is consistent across thousands of pairs.
"""
import hashlib, json, re, sys, itertools
from collections import Counter

PATCHLIST = 'stock-files/com.netease.newspike/files/LocalData/Patch/spike_patchlist_android_astc_512_py3.txt'

pl = json.load(open(PATCHLIST))
pairs = []   # (logical_name, guid_hex32)
for k, v in pl.items():
    if not isinstance(v, list):
        continue
    for item in v:
        if isinstance(item, str) and re.fullmatch(r'[0-9a-f]{2}/[0-9a-fA-F-]{36}(\.\d+)?', item):
            guid = item.split('/')[1].split('.')[0]
            pairs.append((k, guid.replace('-', '').lower()))
print('dlcid->guid pairs:', len(pairs))

def ints_from_digest(dg):
    b = dg.digest()
    out = {}
    out['d0_8_le'] = int.from_bytes(b[0:8], 'little')
    out['d0_8_be'] = int.from_bytes(b[0:8], 'big')
    out['d8_16_le'] = int.from_bytes(b[8:16], 'little')
    out['d8_16_be'] = int.from_bytes(b[8:16], 'big')
    return out

def ints_from_guid(g):
    out = {}
    out['g_all_be'] = int(g, 16)
    out['g_all_le'] = int.from_bytes(bytes.fromhex(g), 'little')
    out['g_first16_be'] = int(g[:16], 16)
    out['g_first16_le'] = int.from_bytes(bytes.fromhex(g[:16]), 'little')
    out['g_last16_be'] = int(g[16:], 16)
    out['g_last16_le'] = int.from_bytes(bytes.fromhex(g[16:]), 'little')
    return out

def score(namefn):
    names = [namefn(k, g) for k, g in pairs]
    for dkey in ('d0_8_le', 'd0_8_be', 'd8_16_le', 'd8_16_be'):
        dig = {n: ints_from_digest(hashlib.md5(n.encode()))[dkey] for n in set(names)}
        for gkey in ('g_all_be', 'g_all_le', 'g_first16_be', 'g_first16_le',
                     'g_last16_be', 'g_last16_le'):
            c = Counter()
            for n, g in zip(names, (x[1] for x in pairs)):
                salt = dig[n] ^ ints_from_guid(g)[gkey]
                c[salt] += 1
            mode, cnt = c.most_common(1)[0]
            if cnt > 1:
                yield (namefn.__name__, dkey, gkey, cnt, len(pairs), mode, c)

namefns = [
    ('dlcid', lambda k, g: k),
    ('guid_nodash', lambda k, g: g),
    ('guid_dash', lambda k, g: '%s-%s-%s-%s-%s' % (g[0:8], g[8:12], g[12:16], g[16:20], g[20:32])),
    ('guid_dir_nodash', lambda k, g: g[:2] + '/' + g),
    ('guid_dir_dash', lambda k, g: g[:2] + '/' + '%s-%s-%s-%s-%s' % (g[0:8], g[8:12], g[12:16], g[16:20], g[20:32])),
]

best = []
for nm, fn in namefns:
    for r in score(fn):
        best.append(r)
best.sort(key=lambda r: -r[3])
for r in best[:12]:
    print('name=%-14s digest=%-8s guid=%-13s agree=%d/%d  salt=0x%016x' %
          (r[0], r[1], r[2], r[3], r[4], r[5]))
