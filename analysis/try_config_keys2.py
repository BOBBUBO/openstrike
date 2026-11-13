#!/usr/bin/env python3
"""Cipher campaign #10 for LocalData/Config*  (validated tagged-config oracle).

Oracle: analysis/tagged_config2.parse_file() must consume the decrypted
buffer *exactly*.  The oracle is self-tested against the known-plaintext
TroyConfig files first.

Key space swept:
  * all 256 single-byte XOR keys
  * repeating XOR with md5/sha1 of ~40 candidate salts (7 encodings each)
  * repeating XOR with the file's own first 16 bytes / md5 of them
  * RC4 with the same candidate salts
  * both "whole file encrypted" and "header (16 B) left in clear"
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tagged_config2 as tc  # noqa: E402

BASE = 'stock-files/com.netease.newspike/files/LocalData'
PATCH = os.path.join(BASE, 'Patch')
HDR = 16


def rc4(key, data):
    S = list(range(256))
    j = 0
    klen = len(key)
    if not klen:
        return data
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for n, c in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[n] = c ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


def xor(data, key):
    n = len(key)
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


def ok(buf, hdr=HDR):
    try:
        items, end = tc.parse_file(buf, hdr)
        return end == len(buf), len(items)
    except Exception:
        return False, 0


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
    'b0979779444', '71ad02b5', 'blood-strike.com', 'messiahForceEncrypt',
]


def md5_forms(salt):
    b = salt.encode() if isinstance(salt, str) else salt
    d = hashlib.md5(b).digest()
    h = hashlib.md5(b).hexdigest().encode()
    yield 'md5raw', d
    yield 'md5hex', h
    yield 'md5hexUP', h.upper()
    yield 'md5_8le', d[:8]
    yield 'md5_8be', d[:8][::-1]
    yield 'md5rot', d[8:] + d[:8]
    yield 'sha1raw', hashlib.sha1(b).digest()


print('--- oracle self-test ---')
for p in [os.path.join(PATCH, 'TroyConfig/Collision.bin'),
          os.path.join(PATCH, 'TroyConfig/Graphics.bin')]:
    b = open(p, 'rb').read()
    good, n = ok(b)
    print('  %-20s len=%-7d parse_exact=%s entries=%d' %
          (os.path.basename(p), len(b), good, n))

hits = []
for fname in ('Config', 'Config_bak', 'Config1', 'LuckyFile'):
    path = os.path.join(BASE, fname)
    if not os.path.exists(path):
        continue
    raw = open(path, 'rb').read()
    print('\n== %s (%d bytes) head=%s' % (fname, len(raw), raw[:20].hex()))
    tests = []

    # single byte xor
    for k in range(256):
        tests.append(('xor1:%02x' % k, xor(raw, bytes([k]))))
    # md5 forms of candidate salts
    for salt in SALT_CANDIDATES:
        for label, key in md5_forms(salt):
            tests.append(('xor:%s:%s' % (salt[:14], label), xor(raw, key)))
        tests.append(('rc4:%s' % salt[:14], rc4(salt.encode(), raw)))
    # self-derived
    tests.append(('self16', xor(raw, raw[:16])))
    tests.append(('md5(self16)', xor(raw, hashlib.md5(raw[:16]).digest())))
    tests.append(('md5(magic)', xor(raw, hashlib.md5(raw[:4]).digest())))

    for label, dec in tests:
        for hdr in (HDR, 0):
            good, n = ok(dec, hdr)
            if good:
                print('   *** %s  hdr=%d  entries=%d' % (label, hdr, n))
                hits.append((fname, label, hdr))
    print('   tested %d candidates' % len(tests))

print('\nTOTAL hits: %d' % len(hits))
for h in hits:
    print('  ', h)
