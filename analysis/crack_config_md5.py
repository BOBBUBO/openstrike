#!/usr/bin/env python3
"""Massive salt sweep for the LocalData/Config cipher (oracle-driven).

The plaintext of Config/Config1/LuckyFile is a tagged binary config
(analysis/tagged_config2.py).  We sweep EVERY printable string found in
libGame.so (plus a few extras) as the salt, derive a 16-byte md5 keystream
from it and check whether the result parses.

Two hypotheses per salt:
  H1  C = P XOR md5(S)   over the whole file
  H2  C = P XOR md5(S)   over everything except the 16-byte header
and two keystream encodings (raw digest / ascii hexdigest).

A cheap structural pre-filter (u16 name_len in 1..64 followed by printable
ASCII) keeps the sweep fast; survivors get the full parser.
"""
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tagged_config2 as tc  # noqa: E402

BASE = 'stock-files/com.netease.newspike/files/LocalData'
LIB = 'decompiled/native/lib/arm64-v8a/libGame.so'
HDR = 16


def xor_int(data, key):
    n = len(key)
    k = key * ((len(data) // n) + 1)
    return (int.from_bytes(data, 'big') ^
            int.from_bytes(k[:len(data)], 'big')).to_bytes(len(data), 'big')


def quick(buf, off):
    """cheap structural check for a named-entry config at `off`"""
    if off + 3 > len(buf):
        return False
    n = int.from_bytes(buf[off:off + 2], 'little')
    if not (1 <= n <= 64) or off + 2 + n > len(buf):
        return False
    name = buf[off + 2:off + 2 + n]
    return all(32 <= c < 127 for c in name)


def full(buf, off):
    try:
        items, end = tc.parse_file(buf, off)
        return end == len(buf), len(items)
    except Exception:
        return False, 0


def candidates():
    d = open(LIB, 'rb').read()
    seen = set()
    for m in re.finditer(rb'[\x20-\x7e]{5,120}', d):
        s = m.group().decode('ascii')
        if s not in seen:
            seen.add(s)
            yield s
    for extra in ('71ad02b5-a3ec-4ec4-9c89-3b0979779444',
                  '1794371578', 'g83naxx1ena', 'g83naxx1ena_1',
                  'bloodstrike', 'newspike', 'messiah', '4!|{',
                  'com.netease.newspike', 'b221cacf', 'Config', 'Config1'):
        if extra not in seen:
            seen.add(extra)
            yield extra


def sweep(fname):
    path = os.path.join(BASE, fname)
    raw = open(path, 'rb').read()
    print('\n=== %s (%d bytes) ===' % (fname, len(raw)))
    hits = []
    n = 0
    for salt in candidates():
        n += 1
        sb = salt.encode()
        dig = hashlib.md5(sb).digest()
        hexd = hashlib.md5(sb).hexdigest().encode()
        for label, key in (('raw', dig), ('hex', hexd)):
            # H1: whole file
            dec = xor_int(raw, key)
            if quick(dec, HDR) or quick(dec, 0):
                good, cnt = full(dec, HDR) or full(dec, 0)
                if good:
                    print('   *** H1 %s salt=%r key=%s entries=%d'
                          % (fname, salt[:40], label, cnt))
                    hits.append((fname, salt, label, 'H1'))
            # H2: header kept in clear
            body = raw[HDR:]
            dec2 = xor_int(body, key)
            if quick(dec2, 0):
                good, cnt = full(dec2, 0)
                if good:
                    print('   *** H2 %s salt=%r key=%s entries=%d'
                          % (fname, salt[:40], label, cnt))
                    hits.append((fname, salt, label, 'H2'))
    print('   swept %d salts' % n)
    return hits


allhits = []
for f in ('LuckyFile', 'Config1', 'Config'):
    if os.path.exists(os.path.join(BASE, f)):
        allhits += sweep(f)
print('\nTOTAL hits: %d' % len(allhits))
for h in allhits[:40]:
    print('  ', h)
