#!/usr/bin/env python3
"""Broad sweep of AES modes/IVs with the AES keys hardcoded in libGame.so
against LocalData/Config, Config1, Config_bak.

Keys (from ntes_gzailab::Encryptor ctor @0x3f74b24 and neighbours):
  0xac0be0[0:16]  -> AES-128
  0xac0be0[0:24]  -> AES-192
  0x70b3f0[0:32]  -> AES-256
  0x708410[0:16]  -> AES-128 (second one)
plus the canonical FIPS-197 vectors.
"""
import binascii
import os
import subprocess

LOCAL = os.path.join(os.path.dirname(__file__), '..', 'stock-files',
                     'com.netease.newspike', 'files', 'LocalData')
SO = 'decompiled/native/lib/arm64-v8a/libGame.so'
b = open(SO, 'rb').read()

KEYS = {
    'k128a': binascii.hexlify(b[0xac0be0:0xac0be0 + 16]).decode(),
    'k192a': binascii.hexlify(b[0xac0be0:0xac0be0 + 24]).decode(),
    'k256a': binascii.hexlify(b[0x70b3f0:0x70b3f0 + 32]).decode(),
    'k128b': binascii.hexlify(b[0x708410:0x708410 + 16]).decode(),
    'fips128': '2b7e151628aed2a6abf7158809cf4f3c',
    'fips192': '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
    'fips256': '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
}
CIPHERS = ['aes-128-ecb', 'aes-192-ecb', 'aes-256-ecb',
           'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc',
           'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
           'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
           'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb']


def run(cipher, keyhex, data, iv=None, skip=0):
    cmd = ['openssl', 'enc', '-' + cipher, '-d', '-nopad', '-K', keyhex, '-nosalt']
    if iv:
        cmd += ['-iv', iv]
    p = subprocess.run(cmd, input=data[skip:], stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
    return p.stdout


def score(d):
    if not d:
        return 0.0, 0
    pr = sum(1 for x in d if 32 <= x < 127 or x in (9, 10, 13)) / len(d)
    hits = 0
    for needle in (b'{', b'['):
        hits += d.count(needle)
    return pr, hits


def main():
    for name in ('Config', 'Config1', 'Config_bak'):
        p = os.path.join(LOCAL, name)
        if not os.path.exists(p):
            continue
        data = open(p, 'rb').read()
        n16 = (len(data) // 16) * 16
        print('=== %s (%d B)' % (name, len(data)))
        results = []
        for cname in CIPHERS:
            bits = cname.split('-')[1]
            for kname, khex in KEYS.items():
                if kname[-3:] != bits:
                    continue
                ivs = [None, '00' * 16]
                if cname.endswith(('cbc', 'ctr', 'cfb', 'ofb')):
                    ivs.append(binascii.hexlify(data[:16]).decode())
                    ivs.append(binascii.hexlify(data[:16]).decode()[:32])
                for iv in ivs:
                    out = run(cname, khex, data[:n16], iv)
                    pr, hits = score(out)
                    results.append((pr, hits, cname, kname, iv, out))
        results.sort(key=lambda x: (-x[0], -x[1]))
        for pr, hits, cname, kname, iv, out in results[:6]:
            print('  %-12s %-8s iv=%-8s printable=%.3f braces=%d %r'
                  % (cname, kname, (iv or 'none')[:8], pr, hits, out[:48]))
        # also: IV taken from the first 16 bytes, data starts after
        for cname in CIPHERS:
            bits = cname.split('-')[1]
            for kname, khex in KEYS.items():
                if kname[-3:] != bits:
                    continue
                if cname.endswith('ecb'):
                    continue
                out = run(cname, khex, data, binascii.hexlify(data[:16]).decode(), skip=16)
                pr, hits = score(out)
                if pr > 0.55 or hits > 20:
                    print('  ** IV-prefix %-12s %-8s printable=%.3f braces=%d %r'
                          % (cname, kname, pr, hits, out[:64]))


if __name__ == '__main__':
    main()
