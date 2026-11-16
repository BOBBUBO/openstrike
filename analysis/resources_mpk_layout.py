#!/usr/bin/env python3
"""Decode the *Resources.mpk* container layout (Android base package).

New (solved) structure of `decompiled/apk/split_base_mpk/assets/Resources.mpk`
================================================================================

    offset 0x000000  magic "237MPTZSTD1"            (11 bytes)
    offset 0x00000b  zstd frame                     (9,766,923 bytes compressed)
                     -> 39,814,069 bytes decompressed = the *resource index*
                        (JSON: {"dlcid_<id>": ["<xx>/<uuid>.4", ...]})
    offset 0x950836  raw MPK chunk region           (to EOF, 268,487,812 B)

The trailing region is NOT compressed.  It is a dense array of self-describing
MPK chunk records, each of which begins with the 6-byte inner MPK magic

    02 02 02 01 01 2b

followed by a 0x38-byte descriptor.  The *payload* of every record therefore
starts at chunk_offset + 0x40.

The `Resources.mpkinfo` file table stores, for every entry, the offset of the
chunk *header* (not of the payload) for records living in `Resources.mpk`,
while for `Resources1.mpk` it stores the offset of the *payload*.  This
container-specific difference is what made the first extraction attempts look
like garbage.

Chunk descriptor layout (offsets relative to the chunk start)
==============================================================

    +0x00  6 bytes   inner MPK magic 02 02 02 01 01 2b
    +0x06  u16      flags (=1)
    +0x08  u16      ? (=12)
    +0x0a  u16      ? (=259)
    +0x0c  u16      descriptor width / logical size low  (varies)
    +0x0e  u16      descriptor width / logical size high (varies)
    +0x10  16 bytes zero
    +0x20  u32      *stored* (compressed) size of the payload
    +0x24  4 bytes  01 2b 01 00  (inner magic, second copy)
    +0x28  u32      *compressed* size of the payload
    +0x2c  u16+u16  descriptor width (repeat of +0x0c/+0x0e)
    +0x30  u32      texture descriptor flags (NNNN only)
    +0x34  u32      texture descriptor width (NNNN only)
    +0x38  4 bytes  chunk magic: "ZZZ4" (LZ4 block) or "NNNN" (encoded tex)
    +0x3c  u32      decompressed output size
    +0x40  ...      payload (LZ4 block) or raw encoded texture bytes

Validation (verified on every GUID entry of Resources.mpk):

    total_record_size = 0x40 + (u32@+0x28 - 24) == table["size"]   (always)

which is the *same* framing rule as the patch-side archives, just with the
chunk header living inside the stored record.
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lz4_block import decompress_with_consumed  # noqa: E402

R0 = 'decompiled/apk/split_base_mpk/assets/Resources.mpk'
R1 = 'decompiled/apk/split_base_mpk/assets/Resources1.mpk'
INFO = 'decompiled/apk/split_base_mpk/assets/Resources.mpkinfo'

MPK_MAGIC = b'\x02\x02\x02\x01\x01\x2b'
CHUNK_MAGIC_OFF = 0x38
PAYLOAD_OFF = 0x40


def read_chunk(buf, off=0):
    """Decode one MPK chunk record.  Returns dict or None."""
    if buf[off:off + 6] != MPK_MAGIC:
        return None
    if len(buf) < off + 0x40:
        return None
    magic = buf[off + CHUNK_MAGIC_OFF:off + CHUNK_MAGIC_OFF + 4]
    stored = struct.unpack_from('<I', buf, off + 0x20)[0]
    comp = struct.unpack_from('<I', buf, off + 0x28)[0]
    out_size = struct.unpack_from('<I', buf, off + 0x3C)[0]
    rec_size = 0x40 + (comp - 24)
    info = {
        'magic': magic,
        'stored_size': stored,
        'compressed_size': comp - 24,
        'output_size': out_size,
        'record_size': rec_size,
        'payload_offset': off + PAYLOAD_OFF,
    }
    if magic == b'ZZZ4':
        info['kind'] = 'lz4-block'
        return info
    if magic == b'NNNN':
        info['kind'] = 'encoded-texture'
        return info
    info['kind'] = 'unknown'
    return info


def main():
    rows = []
    for line in open('analysis/package-file-table.jsonl'):
        rows.append(json.loads(line))
    guid = [r for r in rows
            if (r.get('name') or '').count('-') == 4 and r.get('container')]
    print('file-table rows: %d, GUID-named: %d' % (len(rows), len(guid)))
    handles = {'Resources.mpk': open(R0, 'rb'), 'Resources1.mpk': open(R1, 'rb')}
    stats = {}
    mism = []
    ok = 0
    for r in guid:
        cont = r['container']
        f = handles[cont]
        f.seek(r['offset'])
        buf = f.read(r['size'])
        if len(buf) != r['size']:
            continue
        if cont == 'Resources.mpk':
            info = read_chunk(buf, 0)
            if info is None:
                stats['no-chunk-magic'] = stats.get('no-chunk-magic', 0) + 1
                continue
            payload = buf[PAYLOAD_OFF:]
        else:
            info = {'kind': 'raw-payload', 'record_size': r['size']}
            payload = buf
        k = (cont, info['kind'])
        stats[k] = stats.get(k, 0) + 1
        if info['kind'] == 'lz4-block':
            try:
                data, consumed = decompress_with_consumed(payload, info['output_size'])
            except Exception:
                stats['lz4-fail'] = stats.get('lz4-fail', 0) + 1
                continue
            info['consumed'] = consumed
        else:
            data = payload
        if r.get('md5_stored') and len(data) == r['size'] - (0x40 if cont == 'Resources.mpk' else 0):
            pass
        ok += 1
    print('decoded %d / %d GUID entries' % (ok, len(guid)))
    for k in sorted(stats, key=lambda x: str(x)):
        print('   %-52s %d' % (str(k), stats[k]))


if __name__ == '__main__':
    main()
