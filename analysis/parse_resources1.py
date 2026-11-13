#!/usr/bin/env python3
"""Map Resources1.mpk asset chunks to their manifest file names.

Each asset chunk starts with the tag ``01 2b <ver> 00`` followed by a u32
descriptor length and then the payload.  The chunk size lives in the four
bytes immediately before the tag.  The package also carries JSON manifests
that map a file name to [md5, size]; matching the md5 of each chunk payload
(raw or LZ4 decoded) recovers the mapping.
"""
import hashlib
import json
import re
import struct
import sys

sys.path.insert(0, 'analysis')
from lz4_block import decompress_with_consumed

PATH = 'decompiled/apk/split_base_mpk/assets/Resources1.mpk'
TAG = b'\x01\x2b'


def build_manifest(data):
    text = data.decode('latin-1')
    out = {}
    for name, md5, size in re.findall(
            r'"([^"\\\]]{1,160})":\s*\["([0-9a-f]{32})",\s*(\d+)\]', text):
        out.setdefault(md5, (name, int(size)))
    return out


def main():
    data = open(PATH, 'rb').read()
    by_md5 = build_manifest(data)
    print('manifest md5 entries:', len(by_md5))
    target = 'bb060d6265e9052d549d4b5bdbf3a01d'
    print('essential_py3 ->', by_md5.get(target))

    found = {}
    scanned = 0
    for m in re.finditer(re.escape(TAG), data):
        c = m.start()
        if c < 4:
            continue
        desc_len = struct.unpack_from('<I', data, c + 4)[0]
        if desc_len > 0x2000:
            continue
        size = struct.unpack_from('<I', data, c - 4)[0]
        if size < 0x30 or size > (64 << 20) or c + size > len(data):
            continue
        dstart = c + 8
        dend = dstart + desc_len
        payload = data[dend:c + size]
        if not payload:
            continue
        scanned += 1
        cands = [payload]
        if payload[:4] == b'ZZZ4' and len(payload) >= 8:
            out_size = struct.unpack_from('<I', payload, 4)[0]
            try:
                out, used = decompress_with_consumed(payload[8:], out_size)
                cands.append(out)
            except Exception:
                pass
        for cand in cands:
            h = hashlib.md5(cand).hexdigest()
            if h in by_md5:
                name, fsize = by_md5[h]
                if name not in found:
                    found[name] = {'md5': h, 'size': fsize, 'chunk_offset': c,
                                   'payload_len': len(cand),
                                   'desc_len': desc_len,
                                   'record_header': data[c - 0x24:c].hex()
                                   if c >= 0x24 else ''}
                break
    print('chunks scanned:', scanned)
    print('matched:', len(found), '/', len(by_md5))
    for name in sorted(found)[:40]:
        v = found[name]
        print('   %-52s size=%-9d chunk@0x%-9x payload=%d' %
              (name, v['size'], v['chunk_offset'], v['payload_len']))
    json.dump(found, open('analysis/resources1-matched.json', 'w'), indent=1)
    print('\nessential_py3 ->', found.get('essential_py3'))


if __name__ == '__main__':
    main()
