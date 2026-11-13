#!/usr/bin/env python3
"""Recover the environment-SDK RC4 key.

The file https://nos.gameyw.easebar.com/gameyw-gbox/regular_encode_*.json.one_z6
is  base64 -> RC4(key) -> LZMA -> JSON.
After RC4 decryption the first 13 bytes are a classic .lzma header:
    byte0      = props (lc/lp/pb)      must be < 225 and decode to pb<=4
    bytes1..4  = dictionary size (u32le) power-of-two-ish
    bytes5..12 = uncompressed size (u64le)
so a candidate key can be validated cheaply from 13 keystream bytes.
"""
import base64, re, sys, itertools, string

CT_B64 = '/tmp/regular.json'
CT = base64.b64decode(open(CT_B64, 'rb').read())


def rc4_keystream(key: bytes, n: int):
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 255
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for _ in range(n):
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 255])
    return out


def valid_lzma_header(b: bytes):
    p = b[0]
    if p >= 225:
        return False
    pb = p // 45
    if pb > 4:
        return False
    dictsize = int.from_bytes(b[1:5], 'little')
    if dictsize < (1 << 12) or dictsize > (1 << 30):
        return False
    size = int.from_bytes(b[5:13], 'little')
    if size < 1000 or size > (1 << 32):
        return False
    return True


def try_key(k: bytes):
    ks = rc4_keystream(k, 13)
    plain = bytes(a ^ b for a, b in zip(CT[:13], ks))
    if valid_lzma_header(plain):
        return plain
    return None


def candidates():
    d = open('decompiled/native/lib/arm64-v8a/libGame.so', 'rb').read()
    seen = set()
    for m in re.finditer(rb'[\x20-\x7e]{5,64}', d):
        s = m.group().lower()
        if s not in seen:
            seen.add(s)
            yield s
    for extra in ('g83naxx1ena', 'g83naxx1ena_1', 'bloodstrike', 'blood-strike',
                  'com.netease.newspike', 'messiah', 'newspike', 'netease',
                  'spike', 'MESSIAH', 'g83naxx1me', 'g83naxx2hmt', 'g83naxx2vn'):
        yield extra.lower().encode()


def main():
    n = 0
    for cand in candidates():
        n += 1
        k = cand if isinstance(cand, bytes) else cand.encode()
        p = try_key(k)
        if p:
            print('*** KEY FOUND:', k)
            print('   lzma header:', p.hex())
            full = bytes(a ^ b for a, b in zip(CT, rc4_keystream(k, len(CT))))
            open('/tmp/regular.lzma', 'wb').write(full)
            return 0
    print('no key found among %d candidates' % n)
    return 1


if __name__ == '__main__':
    sys.exit(main())
