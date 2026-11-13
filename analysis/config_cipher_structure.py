#!/usr/bin/env python3
"""Structural analysis of the encrypted LocalData/Config* blobs.

`Config`, `Config_bak`, `Config_write`, `Config1`, `Config1_write` and
`LuckyFile` all start with the two bytes ``bf 5b`` and are near-uniform
in byte distribution (chi^2 ~ 3000 for 165 KB), which is the signature of
a *stream cipher over binary plaintext* rather than of a block cipher in
ECB mode (no repeated 16-byte blocks exist) and rather than of a
compressed payload (no compression signature, no dictionary structure).

This tool establishes the hard constraints that any future key-recovery
attempt has to satisfy:

  1. Config and Config_bak are IDENTICAL for bytes 109 .. 148712
     (148,604 bytes) and differ in 16,069 bytes spread over 171 ranges.
  2. 60 of those 171 ranges have a *constant* XOR difference, e.g.
     bytes 88..108 differ by exactly 0xc7 over all 21 bytes.
  3. The cipher is NOT a byte substitution (the C -> C' map is not
     injective: every ciphertext byte maps to up to 64 different
     counterparts) and is NOT position-class affine for mod 1/2/4/8/16.
  4. Long constant-byte runs are essentially absent: `Config` has exactly
     ONE run of >= 6 equal bytes (offset 30, six 0xb0) and `Config1` has
     none.  The `0xb9` runs at the tails (2 bytes in Config, 5 in
     Config1, 6 in LuckyFile) therefore come from the *plaintext* side
     (zero padding) meeting a keystream that happens to contain 0xb9
     there - or from a plaintext sentinel.
  5. The tail bytes are correlated between the two snapshots:
     Config and Config_bak share the 5-byte suffix prefix b9 b9 b8 bf bc,
     Config1 and LuckyFile share b9 b9 b9 b9 b9.

The plaintext grammar is known (analysis/tagged_config2.py), so any
candidate decryption must make `tagged_config2.parse_file()` consume the
whole buffer exactly.
"""
import os
from collections import defaultdict

BASE = 'stock-files/com.netease.newspike/files/LocalData'
FILES = ('Config', 'Config_bak', 'Config_write', 'Config1', 'Config1_write',
         'LuckyFile')


def load(name):
    p = os.path.join(BASE, name)
    if not os.path.exists(p):
        return None
    return open(p, 'rb').read()


def ranges(diff):
    out = []
    s = p = diff[0]
    for i in diff[1:]:
        if i == p + 1:
            p = i
            continue
        out.append((s, p + 1))
        s = p = i
    out.append((s, p + 1))
    return out


def main():
    print('== heads / tails ==')
    for f in FILES:
        d = load(f)
        if d is None:
            continue
        print('%-14s len=%-7d head=%s tail=%s'
              % (f, len(d), d[:8].hex(), d[-12:].hex()))

    a, b = load('Config'), load('Config_bak')
    if a and b:
        n = min(len(a), len(b))
        diff = [i for i in range(n) if a[i] != b[i]]
        rr = ranges(diff)
        const = [(s, e) for s, e in rr
                 if len({a[i] ^ b[i] for i in range(s, e)}) == 1]
        print('\n== Config vs Config_bak ==')
        print('  differing bytes      : %d' % len(diff))
        print('  contiguous ranges    : %d' % len(rr))
        print('  constant-XOR ranges  : %d' % len(const))
        print('  first/last diff at   : %d / %d' % (diff[0], diff[-1]))
        if const:
            s, e = const[0]
            print('  first const range    : %d..%d xor=0x%02x'
                  % (s, e, a[s] ^ b[s]))
        # identical stretch
        same = [i for i in range(n) if a[i] == b[i]]
        runs = ranges([i for i in range(n) if a[i] != b[i]])
        print('  longest identical run: %d bytes'
              % max((e - s for s, e in
                     [(0, runs[0][0])] +
                     [(runs[i][1], runs[i + 1][0])
                      for i in range(len(runs) - 1)] +
                     [(runs[-1][1], n)]), default=0))

        # is it a byte substitution?
        m = defaultdict(set)
        for i in diff:
            m[a[i]].add(b[i])
        bad = sum(1 for v in m.values() if len(v) > 1)
        print('\n  byte-substitution?  : %s (%d/%d ciphertext bytes have '
              '>1 counterpart)' % ('NO' if bad else 'maybe', bad, len(m)))
        for mod in (1, 2, 4, 8, 16):
            tab = {}
            ok = True
            for i in diff:
                key = (i % mod, a[i])
                if key in tab and tab[key] != b[i]:
                    ok = False
                    break
                tab[key] = b[i]
            print('  affine class mod %-3d: %s' % (mod, ok))

    print('\n== constant-byte runs >= 6 ==')
    for f in FILES:
        d = load(f)
        if d is None:
            continue
        runs = []
        i = 0
        while i < len(d):
            j = i
            while j + 1 < len(d) and d[j + 1] == d[i]:
                j += 1
            if j - i + 1 >= 6:
                runs.append((i, j - i + 1, d[i]))
            i = j + 1
        print('  %-14s %d runs %s' % (f, len(runs), runs[:8]))


if __name__ == '__main__':
    main()
