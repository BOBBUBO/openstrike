#!/usr/bin/env python3
"""Locate the engine code that reads/writes the encrypted LocalData/Config files.

Two independent handles:

 A) the 4-byte file magics  bf5babbb / bf5bb251 / bf5bac a7  (little endian
    0xbbab5bbf, 0x51b25bbf, 0xa7ac5bbf) and the 2-byte prefix 'bf 5b';
 B) the tagged-binary-config tag characters.  The plaintext format used by
    TroyConfig/*.bin and essential_py3 uses the tags  's' 'i' '(' '{' 'v'
    'p' 'M'.  The engine must compare against them, so a tight cluster of
    immediate loads of those byte values is a strong fingerprint of the
    config codec.

Usage: python3 analysis/find_config_codec.py [library.so ...]
"""
import collections
import os
import re
import struct
import sys

LIBS = sys.argv[1:] or [
    'decompiled/native/lib/arm64-v8a/libGame.so',
]
MAGICS = {
    'Config': bytes.fromhex('bf5babbb'),
    'Config1': bytes.fromhex('bf5bb251'),
    'LuckyFile': bytes.fromhex('bf5baca7'),
}
TAGS = set(b"'si({vpM'")

for lib in LIBS:
    if not os.path.exists(lib):
        print('skip', lib)
        continue
    d = open(lib, 'rb').read()
    print('\n=== %s (%d bytes) ===' % (lib, len(d)))
    for name, m in MAGICS.items():
        pos = []
        i = d.find(m)
        while i != -1 and len(pos) < 12:
            pos.append(i)
            i = d.find(m, i + 1)
        if pos:
            print('  magic %-10s %s  at %s' %
                  (name, m.hex(), ' '.join(hex(p) for p in pos)))
    i = d.find(b'\xbf\x5b')
    pos = []
    while i != -1 and len(pos) < 20:
        pos.append(i)
        i = d.find(b'\xbf\x5b', i + 1)
    print('  "bf 5b" occurrences (first 20): %s' % ' '.join(hex(p) for p in pos))

    # ---- B) cluster of tag-character immediates in .text
    #   mov wX, #imm  == 0x52800000 | (imm16<<5) | Rd
    hits = collections.defaultdict(set)
    for off in range(0, len(d) - 4, 4):
        w = struct.unpack_from('<I', d, off)[0]
        if (w & 0x7F800000) == 0x52800000:
            imm = (w >> 5) & 0xFFFF
            if imm in TAGS:
                hits[imm].add(off)
    print('  tag-immediate loads: ' +
          ', '.join('%r=%d' % (chr(k), len(v)) for k, v in sorted(hits.items())))
    # find dense windows
    allpos = sorted(set().union(*hits.values())) if hits else []
    windows = []
    i = 0
    while i < len(allpos):
        j = i
        tags = set()
        while j < len(allpos) and allpos[j] - allpos[i] < 0x100:
            for t, ps in hits.items():
                if allpos[j] in ps:
                    tags.add(t)
            j += 1
        if len(tags) >= 4:
            windows.append((allpos[i], allpos[j - 1], ''.join(sorted(chr(t) for t in tags))))
        i = j
    print('  windows (>=4 distinct tags within 256B): %d' % len(windows))
    for a, b, t in windows[:25]:
        print('     0x%08x-0x%08x  tags=%s' % (a, b, t))
