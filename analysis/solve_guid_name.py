#!/usr/bin/env python3
"""Solve the encrypted-filename (GUID) scheme.

The patch archives store most assets under a *content-addressed-looking*
name of the form

    <xx>/<8-4-4-4-12 hex>            RFC-4122 v4 UUID
    <xx>/<8-4-4-4-12 hex>.<n>        ... with a variant suffix
    <xx>/<32 hex>                    flat MD5-shaped name

`spike_patchlist_android_astc_512_py3.txt` maps

    dlcid_<logical-id>  ->  [<xx>/<guid>.N, ...]
    <xx>/<guid>         ->  [<content md5>, <size>]      (section tables)

This script answers three questions with data:

  1. are the GUIDs RFC-4122 v4?           (version / variant nibble census)
  2. is guid == md5(name) / sha1(name) with uuid4 bit-patching?
  3. is guid == md5(salt + name) for any printable string in libGame.so?

Results (2026-11):
  1. YES - 35,112/35,244 (99.64 %) have version nibble 4 and
     35,164/35,244 (99.78 %) have the RFC variant bits (10xx).
  2. NO  - md5/sha1/sha256 of the raw name (and 4 case variants) never match.
  3. NO  - 605,868 candidate salts x {salt+name, name+salt} x 6 pairs -> 0 hits.

So the encrypted filename is `uuid.UUID(bytes=<128-bit hash>, version=4)`
where the 128-bit hash is *not* a plain hash of the logical id.
"""
import hashlib
import json
import os
import re
import sys

PATCH = ('stock-files/com.netease.newspike/files/LocalData/Patch/'
         'spike_patchlist_android_astc_512_py3.txt')
LIB = 'decompiled/native/lib/arm64-v8a/libGame.so'
GUID_RE = re.compile(
    r'^[0-9a-f]{2}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-'
    r'[0-9a-f]{12}(\.\d+)?$')


def load_pairs(limit=None):
    """(logical id, guid path) pairs from the patch list."""
    j = json.loads(open(PATCH, 'rb').read())
    out = []
    for k, v in j.items():
        if not isinstance(v, list):
            continue
        for item in v:
            if isinstance(item, str) and GUID_RE.match(item):
                out.append((k, item))
                break
    return out[:limit] if limit else out


def guid_bytes(path):
    h = re.sub(r'[^0-9a-f]', '', path.split('/')[-1].split('.')[0])
    return bytes.fromhex(h)


def as_uuid4(d):
    b = bytearray(d)
    b[6] = (b[6] & 0x0f) | 0x40
    b[8] = (b[8] & 0x3f) | 0x80
    return bytes(b)


def census(pairs):
    import collections
    ver = collections.Counter()
    var = collections.Counter()
    for _, g in pairs:
        h = re.sub(r'[^0-9a-f]', '', g.split('/')[-1].split('.')[0])
        ver[h[12]] += 1
        var[h[16]] += 1
    n = len(pairs)
    print('pairs: %d' % n)
    print('version nibble: %s' % dict(sorted(ver.items())))
    print('variant nibble: %s' % dict(sorted(var.items())))
    print('  v4 share       : %.2f %%' % (100.0 * ver['4'] / n))
    print('  RFC-variant    : %.2f %%'
          % (100.0 * sum(var[c] for c in '89ab') / n))


def simple_hashes(pairs, nsample=8):
    sample = [(n, guid_bytes(g)) for n, g in pairs[:nsample]]
    modes = {
        'md5': lambda s: hashlib.md5(s).digest(),
        'md5_uuid4': lambda s: as_uuid4(hashlib.md5(s).digest()),
        'sha1_16': lambda s: hashlib.sha1(s).digest()[:16],
        'sha1_16_uuid4': lambda s: as_uuid4(hashlib.sha1(s).digest()[:16]),
        'sha256_16': lambda s: hashlib.sha256(s).digest()[:16],
        'sha256_16_uuid4': lambda s: as_uuid4(hashlib.sha256(s).digest()[:16]),
    }
    tf = {
        'raw': lambda s: s,
        'lower': lambda s: s.lower(),
        'upper': lambda s: s.upper(),
    }
    hits = 0
    for tname, tf_ in tf.items():
        for mname, mf in modes.items():
            for enc in ('utf-8', 'latin-1'):
                ok = sum(1 for name, g in sample
                         if mf(tf_(name).encode(enc)) == g)
                if ok:
                    hits += 1
                    print('  HIT %s/%s/%s %d/%d'
                          % (tname, mname, enc, ok, len(sample)))
    print('simple-hash hits: %d' % hits)


def salt_sweep(pairs, nsample=6, minlen=3, maxlen=120):
    sample = [(n, guid_bytes(g)) for n, g in pairs[:nsample]]
    pref = [(n, g[:4]) for n, g in sample]
    d = open(LIB, 'rb').read()
    seen = set()
    n = 0
    hits = 0
    for m in re.finditer(rb'[\x20-\x7e]{%d,%d}' % (minlen, maxlen), d):
        salt = m.group()
        if salt in seen:
            continue
        seen.add(salt)
        n += 1
        name = sample[0][0].encode()
        for b in (salt + name, name + salt):
            if hashlib.md5(b).digest()[:4] == pref[0][1]:
                hits += 1
                print('  *** prefix hit salt=%r' % salt[:60])
    print('salts swept: %d  hits: %d' % (n, hits))


if __name__ == '__main__':
    pairs = load_pairs()
    census(pairs)
    simple_hashes(pairs)
    if '--sweep' in sys.argv:
        salt_sweep(pairs)
