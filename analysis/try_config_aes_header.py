#!/usr/bin/env python3
"""AES hypothesis test for LocalData/Config*  (oracle driven).

The first 16 bytes of each of these files look like a per-file header
(4-byte magic + 12-byte id).  A common scheme is to use that header as the
AES key with a CTR/OFB/CBC stream mode - which would produce exactly the
"position-stable keystream, not ECB" behaviour the Config / Config_bak diff
analysis showed.

We try AES-128/192/256 in ECB/CBC/CTR/OFB with key/IV taken from the file's
own header, md5/sha1 of it, or md5 of the whole file, and validate every
result with analysis/tagged_config2.parse_file().
"""
import hashlib
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tagged_config2 as tc  # noqa: E402

BASE = 'stock-files/com.netease.newspike/files/LocalData'
HDR = 16


def aes_decrypt(bits, mode, key, iv, data):
    """AES via the openssl CLI; 'enc -d' reverses the keystream for CTR/OFB."""
    cmd = ['openssl', 'enc', '-aes-%s-%s' % (bits, mode), '-d', '-nopad',
           '-K', key.hex()]
    if mode != 'ecb':
        cmd += ['-iv', iv.hex()]
    p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
    return p.stdout


def ok(buf, off=HDR):
    if not buf:
        return False, 0
    try:
        items, end = tc.parse_file(buf, off)
        return end == len(buf) and len(items) > 0, len(items)
    except Exception:
        return False, 0


CIPHERS = [(b, m) for b in ('128', '192', '256')
           for m in ('ecb', 'cbc', 'ctr', 'ofb')]


def key_material(raw):
    h = raw[:16]
    yield 'hdr16', h
    yield 'hdr16+16', raw[:32]
    yield 'md5(hdr16)', hashlib.md5(h).digest()
    yield 'sha1(hdr16)16', hashlib.sha1(h).digest()[:16]
    yield 'md5(file)', hashlib.md5(raw).digest()
    yield 'hdr16rev', h[::-1]
    yield 'sha256(hdr16)', hashlib.sha256(h).digest()


total = 0
for fname in ('Config', 'Config_bak', 'Config1', 'LuckyFile'):
    path = os.path.join(BASE, fname)
    if not os.path.exists(path):
        continue
    raw = open(path, 'rb').read()
    print('\n=== %s (%d) ===' % (fname, len(raw)))
    found = False
    for kname, key in key_material(raw):
        for bits, mode in CIPHERS:
            klen = int(bits) // 8
            if len(key) < klen:
                continue
            k = key[:klen]
            iv = raw[:16] if mode != 'ecb' else b''
            dec = aes_decrypt(bits, mode, k, iv, raw)
            total += 1
            good, n = ok(dec)
            if good:
                print('   *** %s key=%s aes-%s-%s entries=%d'
                      % (fname, kname, bits, mode, n))
                found = True
            if mode in ('ctr', 'ofb'):
                dec2 = raw[:HDR] + aes_decrypt(bits, mode, k, iv, raw[HDR:])
                total += 1
                good, n = ok(dec2)
                if good:
                    print('   *** %s key=%s aes-%s-%s (hdr clear) entries=%d'
                          % (fname, kname, bits, mode, n))
                    found = True
    if not found:
        print('   no hits')

print('\ntrials:', total)
