#!/usr/bin/env python3
"""Cipher campaign #9 for LocalData/Config*  (tagged-config oracle).

The plaintext of Config / Config1 / LuckyFile is (almost certainly) the same
tagged binary-config grammar used by TroyConfig/*.bin and essential_py3.
A correct key therefore makes the grammar consume the file exactly.

The oracle is self-tested first against the *known plaintext* TroyConfig
files; only then is it applied to the encrypted ones.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tagged_config as tc  # noqa: E402

BASE = 'stock-files/com.netease.newspike/files/LocalData'
PATCH = os.path.join(BASE, 'Patch')


def parse_len(buf):
    """Parse a tagged-config byte string; return bytes consumed or None.

    Accepts an optional leading magic and a trailing trailer.
    """
    for start in (0, 2, 4):
        for open_tag in (b'{',):
            if buf[start:start + 1] != open_tag:
                continue
            try:
                items, end = tc.parse_top(buf[start:])
            except Exception:
                continue
            return end + start, len(items)
    # flat sequence of values
    for start in (0, 2, 4):
        try:
            pos = start
            n = 0
            while pos < len(buf):
                v, pos = tc.parse_value(buf, pos)
                n += 1
                if n > 200000:
                    break
            return pos, n
        except Exception:
            continue
    return None, 0


def xor(data, key):
    n = len(key)
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


def keystreams(salt):
    if isinstance(salt, str):
        salt = salt.encode()
    d = hashlib.md5(salt).digest()
    h = hashlib.md5(salt).hexdigest().encode()
    yield 'md5raw', d
    yield 'md5hex', h
    yield 'md5hexUP', h.upper()
    yield 'md5_8le', d[:8]
    yield 'md5_8be', d[:8][::-1]
    yield 'md5_8le_rot', d[8:] + d[:8]
    yield 'sha1raw', hashlib.sha1(salt).digest()


# ---------------------------------------------------------------- self test
print('--- oracle self-test on known-plaintext files ---')
for p in [os.path.join(PATCH, 'TroyConfig/Collision.bin'),
          os.path.join(PATCH, 'TroyConfig/Graphics.bin')]:
    if os.path.exists(p):
        b = open(p, 'rb').read()
        used, n = parse_len(b)
        print('  %-28s len=%-7d consumed=%-7s items=%d  %s'
              % (os.path.basename(p), len(b), used, n,
                 'OK' if used == len(b) else 'MISMATCH'))

SALT_CANDIDATES = [
    '71ad02b5-a3ec-4ec4-9c89-3b0979779444',
    '71ad02b5-a3ec-4ec4-9c89-3b0979779444-1794371578-1794371578',
    '71ad02b5-a3ec-4ec4-9c89-3b0979779444-1794371578',
    '1794371578', '17943715781794371578',
    'g83naxx1ena', 'g83naxx1ena_1', 'g83naxx1me', 'g83naxx2hmt',
    'g83naxx2vn', 'bloodstrike', 'BloodStrike', 'newspike',
    'com.netease.newspike', 'messiah', 'Messiah', 'MESSIAH',
    '4!|{', '0c', 'Config', 'Config1', 'LuckyFile',
    'g83naxx1ena_b221cacf', 'b221cacf',
    'd2ea3f5ca48b0caa6c6281f5f2251bf7',
    '8022f03148fd2c14f02ad37ad137d19f',
    '71ad02b5a3ec4ec49c893b0979779444',
    'b0979779444', '71ad02b5', 'blood-strike.com',
]

FILES = ['Config', 'Config_bak', 'Config1', 'LuckyFile']
hits = []
for fname in FILES:
    path = os.path.join(BASE, fname)
    if not os.path.exists(path):
        continue
    raw = open(path, 'rb').read()
    print('\n== %s (%d bytes) header=%s' % (fname, len(raw), raw[:4].hex()))
    # 1. single byte
    for k in range(256):
        used, n = parse_len(xor(raw, bytes([k])))
        if used == len(raw):
            print('   *** single-byte XOR %02x PARSES (%d items)' % (k, n))
            hits.append((fname, 'xor1', '%02x' % k))
    # 2. md5-derived
    for salt in SALT_CANDIDATES:
        for label, key in keystreams(salt):
            used, n = parse_len(xor(raw, key))
            if used == len(raw):
                print('   *** %s salt=%r key=%s PARSES (%d items)'
                      % (fname, salt, label, n))
                hits.append((fname, salt, label))
    # 3. self-derived
    for nbytes in (4, 8, 16):
        key = hashlib.md5(raw[:nbytes]).digest()
        used, n = parse_len(xor(raw, key))
        if used == len(raw):
            print('   *** %s md5(first%d) PARSES' % (fname, nbytes))
            hits.append((fname, 'self%d' % nbytes, 'md5'))

print('\nTOTAL hits:', len(hits))
for h in hits:
    print('  ', h)
