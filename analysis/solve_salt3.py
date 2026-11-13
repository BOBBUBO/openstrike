#!/usr/bin/env python3
"""MImporter salt solver (v3).

Key improvement over solve_mimporter_salt{,2}.py:
  * use REAL (logical_path -> guid) pairs recovered from spike_patchlist,
    where one dlcid_* key lists both the plain path and the encrypted
    (GUID) file name;
  * compare the FULL 16-byte md5 digest against the FULL 16-byte GUID
    byte-for-byte, ignoring only the 6 UUID bits that the packer forces
    (version nibble in byte 6, variant bits in byte 8);
  * report per-byte agreement so that "salt applied to only part of the
    digest" hypotheses are visible instead of being hidden by a bad mask.

Usage:  python3 analysis/solve_salt3.py [max_pairs]
"""
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict

PATCHLIST = ('stock-files/com.netease.newspike/files/LocalData/Patch/'
             'spike_patchlist_android_astc_512_py3.txt')
MAX = int(sys.argv[1]) if len(sys.argv) > 1 else 4000

GUID_RE = re.compile(r'^([0-9a-f]{2})/([0-9a-fA-F]{8})-?([0-9a-fA-F]{4})-?'
                     r'([0-9a-fA-F]{4})-?([0-9a-fA-F]{4})-?([0-9a-fA-F]{12})(\.\d+)?$')

pl = json.load(open(PATCHLIST))
logical = defaultdict(list)
encrypted = defaultdict(list)
for k, v in pl.items():
    if not isinstance(v, list):
        continue
    for item in v:
        if not isinstance(item, str):
            continue
        m = GUID_RE.match(item)
        if m:
            hexs = (m.group(2) + m.group(3) + m.group(4) + m.group(5) + m.group(6)).lower()
            encrypted[k].append((hexs, m.group(1), m.group(7) or ''))
        else:
            logical[k].append(item)

# clean 1:1 pairs
pairs = []
for k in logical:
    L, E = logical[k], encrypted.get(k, [])
    if len(L) == 1 and len(E) == 1:
        pairs.append((L[0], E[0][0], E[0][1], E[0][2]))
print('dlcid keys           :', len(logical))
print('clean 1:1 pairs      :', len(pairs))
if not pairs:
    sys.exit('no clean pairs')

# keep-mask: ignore the 6 forced UUID bits (version nibble + variant bits)
KEEP = [0xFF] * 16
KEEP[6] = 0x0F
KEEP[8] = 0x3F


def apply_mask(b):
    return bytes(b[i] & KEEP[i] for i in range(16))


# ---------------------------------------------------------------- inputs
def t_identity(p):
    return p


def t_no_ext(p):
    return p.rsplit('.', 1)[0] if '.' in p.rsplit('/', 1)[-1] else p


def t_basename(p):
    return p.rsplit('/', 1)[-1]


def t_nodir(p):
    return '/'.join(p.split('/')[1:])


def t_slash(p):
    return p.replace('\\', '/')


def t_lower(p):
    return p.lower()


def t_upper(p):
    return p.upper()


def t_script(p):
    return 'Script/Python/' + p


def t_patch(p):
    return 'Patch/' + p


def t_dot(p):
    return '.' + p


def t_slash_prefix(p):
    return '/' + p


def t_upper_slash(p):
    return '/' + p.upper()


def t_rev(p):
    return p[::-1]


TRANSFORMS = {
    'identity': t_identity,
    'no_ext': t_no_ext,
    'basename': t_basename,
    'nodir': t_nodir,
    'lower': t_lower,
    'upper': t_upper,
    'script/': t_script,
    'patch/': t_patch,
    'dot': t_dot,
    '/pfx': t_slash_prefix,
    '/UPPER': t_upper_slash,
    'reverse': t_rev,
}


def hexs_to_bytes(h):
    return bytes.fromhex(h)


def score(digest, guid):
    """returns list of 16 per-byte agreement booleans"""
    return [digest[i] == guid[i] for i in range(16)]


sub = pairs[:MAX]
print('using %d pairs\n' % len(sub))

results = []
for tname, tfn in TRANSFORMS.items():
    ds = {}
    gs = {}
    for logical_path, guidhex, d, ext in sub:
        s = tfn(logical_path)
        ds[s] = hashlib.md5(s.encode('utf-8')).digest()
        gs[s] = apply_mask(hexs_to_bytes(guidhex))
    agree = [0] * 16
    total = 0
    # also test the "suffix-preserving" variant where the .N extension of the
    # guid is appended to the input
    for s, d in ds.items():
        total += 1
        sc = score(d, gs[s])
        for i in range(16):
            if sc[i]:
                agree[i] += 1
    results.append((sum(agree), agree, tname, total))

results.sort(key=lambda r: -r[0])
for tot, agree, tname, n in results:
    print('%-9s  total=%5d/%d   per-byte=%s' %
          (tname, tot, n * 16, ''.join('%3d ' % (a * 100 // n) for a in agree)))
