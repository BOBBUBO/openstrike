#!/usr/bin/env python3
"""Test the reconstructed MImporter.decrypt_string() against the GUID-named
patch records.

Reconstructed algorithm (from analysis/decrypt_string.disasm, 0x3a69dd8):

    def decrypt_string(data):
        n = len(data)
        r = (n - 8) % 37            # magic-multiply division by 37 @0x3a69ec0
        v = data[0 : 128 - r]       # slice object built by 0x37a3afc(start,stop,step)
        out = <copy of v>           # 0x3a6129c
        for i in range(len(out)):
            out[i] = out[i] ^ 154   # eor x0,x8,x24 with x24 = 0x9a @0x3a6a194
        return out

The header magic is fixed across every encrypted module, so the most common
first-4-bytes value over the whole encrypted namespace identifies it.
"""
import collections
import ctypes
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mpk_extract import decode_entry  # noqa: E402

XOR_KEY = 154


def header_len(n):
    return 128 - ((n - 8) % 37)


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    out_json = sys.argv[2] if len(sys.argv) > 2 else 'analysis/decrypt_header_histo.json'
    recs = [json.loads(l) for l in open('analysis/patch-records.jsonl')]
    # GUID-named records only (the encrypted namespace).
    recs = [r for r in recs if '/' in r['path'] and r['path'].endswith('.4')]
    print('guid records', len(recs))
    files = {}
    hist4 = collections.Counter()
    hist8 = collections.Counter()
    samples = {}
    ok = 0
    err = 0
    for r in recs[:limit]:
        p = r['archive']
        if p not in files:
            files[p] = open(p, 'rb')
        f = files[p]
        f.seek(r['archive_offset'])
        raw = f.read(r['stored_size'])
        if len(raw) != r['stored_size']:
            err += 1
            continue
        try:
            payload, kind, _ = decode_entry(raw)
        except Exception:
            err += 1
            continue
        n = len(payload)
        hl = header_len(n)
        if hl <= 0 or hl > n:
            err += 1
            continue
        dec = bytes(b ^ XOR_KEY for b in payload[:hl])
        k4 = dec[:4]
        k8 = dec[:8]
        hist4[k4] += 1
        hist8[k8] += 1
        if k4 not in samples:
            samples[k4] = {'path': r['path'], 'size': n, 'dec': dec.hex()}
        ok += 1
        if ok % 2000 == 0:
            print('  ...%d ok, %d err, distinct4=%d' % (ok, err, len(hist4)))
    print('decoded %d, errors %d' % (ok, err))
    print('--- top 12 first-4-byte values ---')
    for k, v in hist4.most_common(12):
        print('  %s  %6d  %s' % (k.hex(), v, samples[k]['path']))
    print('--- top 6 first-8-byte values ---')
    for k, v in hist8.most_common(6):
        print('  %s  %6d' % (k.hex(), v))
    json.dump({'count': ok, 'hist4': [[k.hex(), v] for k, v in hist4.most_common(64)],
               'samples': {k.hex(): samples[k] for k in list(samples)[:64]}},
              open(out_json, 'w'), indent=1)


if __name__ == '__main__':
    main()
