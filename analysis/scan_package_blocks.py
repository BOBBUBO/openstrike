#!/usr/bin/env python3
"""Scan Resources1.mpk (the package data container) for interesting payloads.

Looks for:
  * LZ4 (ZZZ4) blocks whose plaintext is text / JSON / python-ish
  * blocks that decompress with zlib
  * blocks containing tell-tale strings (prerequisite, essential, import,
    .py, MImporter, ...)
"""
import collections
import hashlib
import json
import os
import re
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(__file__))
from lz4_block import decompress

PATH = sys.argv[1] if len(sys.argv) > 1 else 'analysis/apk-split-base/assets/Resources1.mpk'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'analysis/resources1-blocks.jsonl'

data = open(PATH, 'rb').read()
print('file', PATH, len(data))

NEEDLES = [b'prerequisite', b'essential', b'.py', b'import ', b'def ', b'class ',
           b'MImporter', b'asyncore', b'asiocore', b'AccountManager', b'__main__',
           b'compile(', b'exec(', b'marshal', b'zlib', b'decrypt', b'encrypt']

out = open(OUT, 'w')
kinds = collections.Counter()
hits = []
pos = 0
nblocks = 0
while True:
    z = data.find(b'ZZZ4', pos)
    if z < 0:
        break
    pos = z + 1
    if z < 0x20:
        continue
    f1 = struct.unpack_from('<I', data, z - 0x10)[0]
    f2 = struct.unpack_from('<I', data, z - 0x18)[0]
    if f2 != f1 + 8 or f1 < 24:
        continue
    csize = f1 - 24
    osize = struct.unpack_from('<I', data, z + 4)[0]
    if csize > len(data) - z - 8 or osize > 64 * 1024 * 1024:
        continue
    try:
        dec = decompress(data[z + 8:z + 8 + csize], osize)
    except Exception:
        continue
    nblocks += 1
    kind = 'binary'
    preview = dec[:64]
    try:
        txt = dec[:4096].decode('utf-8')
        if re.match(r'^[\s]*[\[{<A-Za-z_#]', txt):
            kind = 'text'
    except UnicodeDecodeError:
        pass
    # zlib inside?
    zl = None
    try:
        zl = zlib.decompress(dec)
        kind += '+zlib'
    except Exception:
        pass
    found = [n.decode() for n in NEEDLES if n in dec]
    if zl:
        found += ['zlib:' + n.decode() for n in NEEDLES if n in zl]
    kinds[kind] += 1
    rec = {
        'offset': z,
        'compressed_size': csize,
        'output_size': len(dec),
        'md5': hashlib.md5(dec).hexdigest(),
        'kind': kind,
        'needles': found,
        'preview': ''.join(chr(c) if 32 <= c < 127 else '.' for c in preview),
    }
    out.write(json.dumps(rec, ensure_ascii=False) + '\n')
    if found:
        hits.append(rec)
        print('HIT', hex(z), len(dec), found, rec['preview'][:80])
out.close()
print('blocks', nblocks, 'kinds', kinds)
print('hits', len(hits))
