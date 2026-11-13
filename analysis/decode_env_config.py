#!/usr/bin/env python3
"""Decoder for NetEase's "environment" (content-moderation) SDK payload.

Chain (recovered from com.netease.environment.* in the APK):

    base64(text)  ->  RC4(key)  ->  LZMA (5-byte header + u64LE size)  ->  JSON

The RC4 key is the *second* argument of ``EnvManager.initSDK(ctx, gameid,
key, secret)``; it is lower-cased by the SDK before use.  ``Channel.startEnvironment``
is invoked from native code, so the key is NOT a plain string inside
libGame.so (0 hits for the game id / package name).

The two files the SDK keeps on disk are

    <app>/files/com/netease/environment/temp/<gameid>_temp.txt   downloaded (b64)
    <app>/files/com/netease/environment/file/<gameid>_regex.txt   base64(RC4(json))

Usage:
    python3 analysis/decode_env_config.py --key <rc4key> [--file <path>]
"""
import argparse
import base64
import lzma
import sys


def rc4(key: bytes, data: bytes) -> bytes:
    if not 5 <= len(key) <= 255:
        raise ValueError('RC4 key length has to be between 5 and 255')
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 255
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for n, c in enumerate(data):
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out[n] = c ^ S[(S[i] + S[j]) & 255]
    return bytes(out)


def lzma_decode(raw: bytes) -> bytes:
    """The SDK's LZMA wrapper: 5-byte props header + u64LE uncompressed size.

    That is exactly the classic ".lzma / alone" container, so Python's
    FORMAT_ALONE decoder handles it directly.  A raw-filter fallback is kept
    for payloads whose size field is 0xFFFFFFFFFFFFFFFF.
    """
    if len(raw) < 13:
        raise ValueError('payload too short')
    try:
        return lzma.decompress(raw, format=lzma.FORMAT_ALONE)
    except lzma.LZMAError:
        pass
    props = raw[:5]
    size = int.from_bytes(raw[5:13], 'little')
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                filters=[{'id': lzma.FILTER_LZMA1,
                                          'dict_size': int.from_bytes(props[1:5], 'little'),
                                          'lc': props[0] % 9,
                                          'lp': (props[0] // 9) % 5,
                                          'pb': props[0] // 45}])
    return dec.decompress(raw[13:], max_length=size if 0 < size < (1 << 62) else -1)


def decode(b64_text: bytes, key: str) -> bytes:
    raw = base64.b64decode(b64_text)
    return lzma_decode(rc4(key.lower().encode('utf-8'), raw))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--key', required=True)
    ap.add_argument('--file', default=None)
    ap.add_argument('--out', default=None)
    a = ap.parse_args()
    path = a.file or ('stock-files/com.netease.newspike.1/files/com/netease/environment/'
                       'temp/g83naxx1ena_temp.txt')
    data = open(path, 'rb').read()
    try:
        plain = decode(data, a.key)
    except Exception as e:
        print('decode failed: %s' % e)
        return 1
    if a.out:
        open(a.out, 'wb').write(plain)
        print('wrote %d bytes to %s' % (len(plain), a.out))
    else:
        sys.stdout.buffer.write(plain[:200000])
    return 0


if __name__ == '__main__':
    sys.exit(main())
