#!/usr/bin/env python3
"""Try the AES keys embedded in libGame.so against LocalData/Config* blobs.

The ntes_gzailab::Encryptor ctor (0x3f74b24) selects AES-128/192/256 from
the first three characters of a key string ("128"/"192"/"256") and then
copies a HARDCODED key block out of .rodata:

  0xac0be0 : 24 bytes  (AES-128 key = first 16, AES-192 key = all 24)
  0x70b3f0 : 32 bytes  (AES-256 key)
  0x708410 : 16 bytes  (another AES-128 candidate)

They are mangled FIPS-197 test vectors.
"""
import binascii
import os
import subprocess
import sys

LOCAL = os.path.join(os.path.dirname(__file__), '..', 'stock-files',
                     'com.netease.newspike', 'files', 'LocalData')
SO = 'decompiled/native/lib/arm64-v8a/libGame.so'
b = open(SO, 'rb').read()

K128_A = binascii.hexlify(b[0xac0be0:0xac0be0 + 16]).decode()
K192_A = binascii.hexlify(b[0xac0be0:0xac0be0 + 24]).decode()
K256_A = binascii.hexlify(b[0x70b3f0:0x70b3f0 + 32]).decode()
K128_B = binascii.hexlify(b[0x708410:0x708410 + 16]).decode()
# canonical FIPS-197 vectors, just in case
K128_FIPS = '2b7e151628aed2a6abf7158809cf4f3c'
K192_FIPS = '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'
K256_FIPS = '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'

KEYS = [
    ('aes-128-ecb', K128_A), ('aes-192-ecb', K192_A), ('aes-256-ecb', K256_A),
    ('aes-128-ecb', K128_B), ('aes-128-ecb', K128_FIPS),
    ('aes-192-ecb', K192_FIPS), ('aes-256-ecb', K256_FIPS),
]


def try_decrypt(cipher, keyhex, data, iv=None):
    cmd = ['openssl', 'enc', '-' + cipher, '-d', '-nopad', '-K', keyhex, '-nosalt']
    if iv:
        cmd += ['-iv', iv]
    p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return p.stdout


def score(d):
    if not d:
        return -1
    pr = sum(1 for x in d if 32 <= x < 127 or x in (9, 10, 13)) / len(d)
    return pr


def main():
    for name in ('Config', 'Config1', 'Config_bak'):
        p = os.path.join(LOCAL, name)
        if not os.path.exists(p):
            continue
        data = open(p, 'rb').read()
        n16 = (len(data) // 16) * 16
        print('=== %s (%d bytes, %d full blocks)' % (name, len(data), n16 // 16))
        best = []
        for cipher, keyhex in KEYS:
            for iv in (None, '00' * 16):
                out = try_decrypt(cipher, keyhex, data[:n16], iv)
                s = score(out)
                tag = '%s%s' % (cipher, '/iv0' if iv else '')
                best.append((s, tag, out[:96]))
                if s > 0.6:
                    print('  *** %s key=%s  printable=%.3f' % (tag, keyhex, s))
                    print('      %r' % out[:200])
        best.sort(key=lambda x: -x[0])
        for s, tag, head in best[:4]:
            print('   %-18s printable=%.3f  %r' % (tag, s, head[:64]))


if __name__ == '__main__':
    main()
