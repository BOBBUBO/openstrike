#!/usr/bin/env python3
"""Attack the LocalData/Config* cipher using the now-known plaintext structure.

Facts established this session:
  * The *package* config format (`TroyConfig/*.bin`) is:
        file := md5(body)[16] || body
        body := tagged-binary-config grammar (analysis/tagged_config2.py)
    -> verified: md5(body) == header for 4/4 TroyConfig files.
  * The *local* config blobs (LocalData/Config, Config1, LuckyFile) start with
    the 2-byte magic `bf 5b`, then a type byte, then 12 more bytes, and the
    rest is ciphertext (663 random-looking ASCII runs, no readable names).

This script brute-forces keystreams derived from the embedded 16-byte header
and scores the result with a *structural* oracle:
  1. a tagged-config parse that consumes the buffer exactly, and
  2. an ASCII-name-density score over the first bytes.
"""
import hashlib
import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tagged_config2 as T  # noqa: E402

D = 'stock-files/com.netease.newspike/files/LocalData/'
BLOBS = ('Config', 'Config1', 'LuckyFile')


def rc4(key, n):
    S = list(range(256))
    j = 0
    klen = len(key)
    if not klen:
        return b''
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def score(buf):
    """Structural score of a candidate plaintext body."""
    s = 0.0
    try:
        items = T.parse_file(buf, header=16)
        s += 1000 + len(items)
    except Exception:
        pass
    try:
        items = T.parse_file(buf, header=0)
        s += 1000 + len(items)
    except Exception:
        pass
    head = buf[:400]
    printable = sum(1 for c in head if 32 <= c < 127)
    s += printable / max(1, len(head)) * 10
    # ASCII-name density: 3+ letter runs
    import re
    runs = re.findall(rb'[A-Za-z_][A-Za-z0-9_]{2,}', head)
    s += len(runs) * 2
    return s


def candidates(head):
    """Yield (label, keystream_generator) pairs derived from the header."""
    h = head
    regions = {
        'h[0:16]': h[0:16],
        'h[2:16]': h[2:16],
        'h[4:16]': h[4:16],
        'h[3:16]': h[3:16],
        'h[4:8]': h[4:8],
        'h[8:16]': h[8:16],
        'h[0:4]': h[0:4],
    }
    for rname, r in regions.items():
        if not r:
            continue
        yield ('rc4:' + rname, lambda r=r: rc4(r, 1 << 16))
        yield ('rc4hex:' + rname,
               lambda r=r: rc4(r.hex().encode(), 1 << 16))
        yield ('rc4HEX:' + rname,
               lambda r=r: rc4(r.hex().upper().encode(), 1 << 16))
        yield ('rep:' + rname, lambda r=r: (r * 4096))
        yield ('reprev:' + rname, lambda r=r: (r[::-1] * 4096))
        yield ('md5:' + rname,
               lambda r=r: (hashlib.md5(r).digest() * 4096))
        yield ('md5hex:' + rname,
               lambda r=r: (hashlib.md5(r).hexdigest().encode() * 4096))
    # plain constant XOR keys
    for k in (154, 0x9a, 0x5b, 0xbf):
        yield ('const:%d' % k, lambda k=k: bytes([k]) * (1 << 16))


def main():
    for fn in BLOBS:
        p = D + fn
        if not os.path.exists(p):
            continue
        raw = open(p, 'rb').read()
        head, body = raw[:16], raw[16:]
        best = []
        for label, gen in candidates(head):
            ks = gen()
            if len(ks) < len(body):
                ks = ks + bytes(len(body) - len(ks))
            dec = xor(body, ks[:len(body)])
            s = score(dec)
            best.append((s, label, dec))
        best.sort(reverse=True, key=lambda t: t[0])
        print('== %s (%d bytes) header=%s' % (fn, len(raw), head.hex()))
        for s, label, dec in best[:6]:
            print('   %-16s score=%8.2f  %r' % (label, s, dec[:48].decode('latin1')))
        sys.stdout.flush()


if __name__ == '__main__':
    main()
