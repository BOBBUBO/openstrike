#!/usr/bin/env python3
"""Recover the repeating-key XOR used for LocalData/Config* blobs.

Observations that motivate this:
  * Config and Config_bak share an identical 148604-byte prefix and differ
    only afterwards -> deterministic stream cipher with a STATIC key, and the
    plaintext prefix is unchanged between versions.
  * No zlib/gzip/lz4/zstd/AES signature anywhere.
  * Long runs of a repeated byte at the very end of Config1
    (b9 b9 b9 b9 b9) -> the key is a short repeating byte string and the
    plaintext there is a run of identical bytes.

Method: index-of-coincidence style autocorrelation to get the key length,
then per-column frequency analysis (the plaintext is JSON / mostly ASCII,
so the dominant plaintext byte is a good guess for the key byte).
"""
import collections
import json
import os
import sys

LOCAL = os.path.join(os.path.dirname(__file__), '..', 'stock-files',
                     'com.netease.newspike', 'files', 'LocalData')


def autocorr(data, maxshift=4096):
    n = len(data)
    scores = []
    for s in range(1, maxshift):
        a = data[:n - s]
        b = data[s:]
        same = sum(1 for x, y in zip(a, b) if x == y)
        scores.append((same / len(a), s))
    scores.sort(reverse=True)
    return scores


def main():
    blobs = {}
    for name in ('Config', 'Config1', 'Config_bak'):
        p = os.path.join(LOCAL, name)
        if os.path.exists(p):
            blobs[name] = open(p, 'rb').read()
    data = blobs['Config']
    print('Config len', len(data))
    sc = autocorr(data, 2048)
    print('\ntop autocorrelation shifts:')
    for v, s in sc[:25]:
        print('  shift %5d  match=%.4f' % (s, v))

    # pick the best candidate key lengths: small shifts with high score whose
    # multiples also score high
    print('\nchecking multiples of candidate base periods:')
    best = []
    for v, s in sc[:60]:
        if s < 1:
            continue
        # require the multiple 2*s and 3*s to also be "good"
        tot = 0
        cnt = 0
        for k in (1, 2, 3, 4):
            d = {ss: vv for vv, ss in sc}
            if k * s in d:
                tot += d[k * s]
                cnt += 1
        if cnt:
            best.append((tot / cnt, s))
    best.sort(reverse=True)
    for avg, s in best[:15]:
        print('  base period %4d  avg-multiple score %.4f' % (s, avg))

    # column analysis for the most promising periods
    for L in sorted({s for _, s in best[:8]} | {16, 32, 64, 128, 256, 512, 1024}):
        cols = [collections.Counter(data[i::L]) for i in range(L)]
        # score: how peaked is each column (max count / len)
        peaks = []
        for i, c in enumerate(cols):
            tot = sum(c.values())
            peaks.append((c.most_common(1)[0][1] / tot, i, c.most_common(3)))
        avg = sum(p[0] for p in peaks) / len(peaks)
        print('\nL=%4d  mean column peak ratio %.3f' % (L, avg))
        key = bytes(c.most_common(1)[0][0] for c in cols)
        print('  key guess: %s' % key.hex())
        dec = bytes(data[i] ^ key[i % L] for i in range(len(data)))
        printable = sum(1 for b in dec[:4096] if 32 <= b < 127 or b in (9, 10, 13))
        print('  printable ratio of first 4K: %.3f' % (printable / 4096))
        print('  head: %r' % dec[:96])


if __name__ == '__main__':
    main()
