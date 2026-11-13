#!/usr/bin/env python3
"""MImporter salt solver (v4) - mode based.

The pack manifest lists, under one dlcid_* key, BOTH the plain asset paths
and the encrypted (GUID) file names of the same content.  We therefore do not
need a 1:1 mapping: for a candidate hypothesis we take every (logical, guid)
combination inside a dlcid, derive the implied per-byte XOR between the md5
digest of the logical name and the 16 GUID bytes, and look for a byte-wise
mode.  Under the correct hypothesis at least one combination per dlcid is
right, so every byte position shows a dominant value (~1 hit per dlcid);
under a wrong hypothesis the mode is pure noise (~1/256).

Usage:  python3 analysis/solve_salt4.py [max_candidates]
"""
import hashlib
import json
import random
import re
import sys
from collections import Counter

PATCHLIST = ('stock-files/com.netease.newspike/files/LocalData/Patch/'
             'spike_patchlist_android_astc_512_py3.txt')
MAXC = int(sys.argv[1]) if len(sys.argv) > 1 else 400000

GUID_RE = re.compile(r'^([0-9a-f]{2})/([0-9a-fA-F]{8})-?([0-9a-fA-F]{4})-?'
                     r'([0-9a-fA-F]{4})-?([0-9a-fA-F]{4})-?([0-9a-fA-F]{12})(\.\d+)?$')

pl = json.load(open(PATCHLIST))
groups = []
for k, v in pl.items():
    if not isinstance(v, list):
        continue
    L, E = [], []
    for item in v:
        if not isinstance(item, str):
            continue
        m = GUID_RE.match(item)
        if m:
            hexs = (m.group(2) + m.group(3) + m.group(4) + m.group(5) + m.group(6)).lower()
            E.append((hexs, m.group(1), m.group(7) or ''))
        else:
            L.append(item)
    if L and E:
        groups.append((L, E))
print('groups (dlcid with both logical+guid):', len(groups))

rnd = random.Random(1234)
cands = []
for L, E in groups:
    n = len(L) * len(E)
    if n > 40:
        for _ in range(40):
            cands.append((rnd.choice(L), rnd.choice(E)))
    else:
        for l in L:
            for e in E:
                cands.append((l, e))
if len(cands) > MAXC:
    rnd.shuffle(cands)
    cands = cands[:MAXC]
print('candidate pairs:', len(cands))

# ------------------------------------------------------------------ inputs
def ext_of(p):
    b = p.rsplit('/', 1)[-1]
    return '.' + b.rsplit('.', 1)[-1] if '.' in b else ''


TRANSFORMS = {
    'identity':   lambda p, e: p,
    'no_ext':     lambda p, e: p[:-len(ext_of(p))] if ext_of(p) else p,
    'basename':   lambda p, e: p.rsplit('/', 1)[-1],
    'basename_noext': lambda p, e: (lambda b: b[:-len(ext_of(p))] if ext_of(p) else b)(p.rsplit('/', 1)[-1]),
    'nodir':      lambda p, e: '/'.join(p.split('/')[1:]),
    'lower':      lambda p, e: p.lower(),
    'upper':      lambda p, e: p.upper(),
    'script/':    lambda p, e: 'Script/Python/' + p,
    'Script/Python/': lambda p, e: 'Script/Python/' + p,
    'Lib3/':      lambda p, e: 'Lib3/' + p,
    '/Lib3/':     lambda p, e: '/Lib3/' + p,
    'patch/':     lambda p, e: 'Patch/' + p,
    'Patch/':     lambda p, e: 'Patch/' + p,
    'dot':        lambda p, e: '.' + p,
    '/pfx':       lambda p, e: '/' + p,
    '/UPPER':     lambda p, e: '/' + p.upper(),
    'UPPER_slash': lambda p, e: '/' + p.upper(),
    'guid_ext':   lambda p, e: p + e[2],
    'guid_ext_up': lambda p, e: p + e[2].upper(),
    'dlcid_guid': lambda p, e: e[1],
    'slash_only': lambda p, e: p.replace('\\', '/'),
    'fullpath':   lambda p, e: p if p.startswith('/') else '/' + p,
}


def guid_bytes(hexs):
    return bytes.fromhex(hexs)


best = []
for tname, tfn in TRANSFORMS.items():
    counts = [Counter() for _ in range(16)]
    n = 0
    for logical, e in cands:
        s = tfn(logical, e)
        try:
            d = hashlib.md5(s.encode('utf-8')).digest()
        except Exception:
            continue
        g = guid_bytes(e[0])
        n += 1
        for i in range(16):
            counts[i][d[i] ^ g[i]] += 1
    modes = [c.most_common(1)[0] for c in counts]
    score = sum(m[1] for m in modes)
    best.append((score, n, tname, modes, counts))

best.sort(key=lambda r: -r[0])
print('\n%-16s %8s %8s  %s' % ('transform', 'score', 'n', 'per-byte mode counts'))
for score, n, tname, modes, counts in best:
    print('%-16s %8d %8d  %s' %
          (tname, score, n, ' '.join('%5d' % m[1] for m in modes)))

score, n, tname, modes, counts = best[0]
print('\nBEST: %s  score=%d/%d (n*16=%d)' % (tname, score, n, n * 16))
print('implied salt bytes (digest XOR guid):')
for i, (v, c) in enumerate(modes):
    print('   byte %2d : 0x%02x  (mode hits %d / %d)' % (i, v, c, n))
