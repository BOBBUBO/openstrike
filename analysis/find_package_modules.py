#!/usr/bin/env python3
"""Apply the reconstructed MImporter.decrypt_string() to every GUID-named
entry of the Android package (Resources1.mpk + the decompressed Resources.mpk)
and report entries whose decrypted header becomes readable text.

decrypt_string(data):
    n  = len(data)
    r  = (n - 8) % 37
    v  = data[0 : 128 - r]
    out[i] = v[i] ^ 154   for i in range(len(v))
"""
import ctypes
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mpk_extract import decode_entry  # noqa: E402

XOR_KEY = 154
R1 = 'decompiled/apk/split_base_mpk/assets/Resources1.mpk'
R0 = 'decompiled/apk/split_base_mpk/assets/Resources.mpk'
DEC = '/tmp/Resources.dec.mpk'


def decompress_resources_mpk():
    if os.path.exists(DEC) and os.path.getsize(DEC) > 1000000:
        return DEC
    lib = ctypes.CDLL('libzstd.so.1')
    raw = open(R0, 'rb').read()
    assert raw[:11] == b'237MPTZSTD1', raw[:16]
    comp = raw[11:]
    # streaming decompression: the container may hold several concatenated
    # zstd frames.
    lib.ZSTD_createDStream.restype = ctypes.c_void_p
    lib.ZSTD_initDStream.argtypes = [ctypes.c_void_p]
    lib.ZSTD_initDStream.restype = ctypes.c_size_t
    lib.ZSTD_decompressStream.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_void_p]
    lib.ZSTD_decompressStream.restype = ctypes.c_size_t
    lib.ZSTD_isError.restype = ctypes.c_uint
    lib.ZSTD_DStreamOutSize.restype = ctypes.c_size_t
    ds = lib.ZSTD_createDStream()
    lib.ZSTD_initDStream(ds)

    class Buf(ctypes.Structure):
        _fields_ = [('dst', ctypes.c_void_p), ('size', ctypes.c_size_t),
                    ('pos', ctypes.c_size_t)]

    class InBuf(ctypes.Structure):
        _fields_ = [('src', ctypes.c_void_p), ('size', ctypes.c_size_t),
                    ('pos', ctypes.c_size_t)]

    chunk = lib.ZSTD_DStreamOutSize()
    outbuf = ctypes.create_string_buffer(chunk)
    inbuf = InBuf(ctypes.cast(ctypes.c_char_p(comp), ctypes.c_void_p), len(comp), 0)
    total = 0
    with open(DEC, 'wb') as fh:
        while inbuf.pos < inbuf.size:
            obuf = Buf(ctypes.cast(outbuf, ctypes.c_void_p), chunk, 0)
            r = lib.ZSTD_decompressStream(ds, ctypes.byref(obuf), ctypes.byref(inbuf))
            if lib.ZSTD_isError(r):
                raise RuntimeError('zstd error %d at pos %d' % (r, inbuf.pos))
            if obuf.pos:
                fh.write(outbuf.raw[:obuf.pos])
                total += obuf.pos
            if r == 0 and inbuf.pos >= inbuf.size:
                break
            if obuf.pos == 0 and r == 0 and inbuf.pos >= inbuf.size:
                break
    print('decompressed Resources.mpk -> %s (%d bytes)' % (DEC, total))
    return DEC


def pr(b):
    if not b:
        return 0.0
    return sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / len(b)


def main():
    decompress_resources_mpk()
    handles = {R1: open(R1, 'rb'), R0: open(R0, 'rb')}
    rows = []
    for l in open('analysis/package-file-table.jsonl'):
        r = json.loads(l)
        nm = r.get('name') or ''
        if '-' in nm.split('/')[-1]:
            rows.append(r)
    print('uuid entries', len(rows))
    hits = []
    seen = 0
    for r in rows:
        cont = r.get('container')
        path = R1 if cont == 'Resources1.mpk' else R0
        f = handles[path]
        f.seek(r['offset'])
        b = f.read(r['size'])
        if len(b) != r['size']:
            continue
        seen += 1
        try:
            b, kind, _ = decode_entry(b)
        except Exception:
            continue
        n = len(b)
        hl = 128 - ((n - 8) % 37)
        if hl <= 8 or hl > n:
            continue
        head = b[:hl]
        dec = bytes(x ^ XOR_KEY for x in head)
        p = pr(dec)
        rp = pr(head)
        if p > 0.8 and rp < 0.55:
            hits.append({'name': r['name'], 'size': n, 'printable': round(p, 3),
                         'raw_printable': round(rp, 3), 'container': cont,
                         'decoded': dec[:200].decode('latin1')})
        if seen % 4000 == 0:
            print('  ...%d / %d, hits %d' % (seen, len(rows), len(hits)))
    print('scanned %d, hits %d' % (seen, len(hits)))
    json.dump(hits, open('analysis/package_decrypt_candidates.json', 'w'), indent=1)
    hits.sort(key=lambda h: (-h['printable'], h['size']))
    for h in hits[:30]:
        print('%-52s size=%-7d pr=%.2f raw=%.2f | %r' %
              (h['name'], h['size'], h['printable'], h['raw_printable'],
               h['decoded'][:70]))


if __name__ == '__main__':
    main()
