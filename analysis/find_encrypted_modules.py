#!/usr/bin/env python3
"""Find encrypted Python modules by applying the reconstructed
MImporter.decrypt_string() and looking for a header that becomes readable
text after the XOR-154 step.

decrypt_string(data):
    n  = len(data)
    r  = (n - 8) % 37
    v  = data[0 : 128 - r]
    out[i] = v[i] ^ 154   for i in range(len(v))

An encrypted module's first bytes are high-entropy (text XOR 154), so the
decrypted header should be overwhelmingly printable ASCII while the raw bytes
are not.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mpk_extract import decode_entry  # noqa: E402

XOR_KEY = 154


def printable_ratio(b):
    if not b:
        return 0.0
    return sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / len(b)


def main():
    recs = [json.loads(l) for l in open('analysis/patch-records.jsonl')]
    files = {}
    hits = []
    seen = 0
    for r in recs:
        p = r['archive']
        if p not in files:
            files[p] = open(p, 'rb')
        f = files[p]
        f.seek(r['archive_offset'])
        raw = f.read(r['stored_size'])
        if len(raw) != r['stored_size']:
            continue
        try:
            payload, kind, _ = decode_entry(raw)
        except Exception:
            continue
        n = len(payload)
        hl = 128 - ((n - 8) % 37)
        if hl <= 8 or hl > n:
            continue
        head = payload[:hl]
        dec = bytes(b ^ XOR_KEY for b in head)
        pr = printable_ratio(dec)
        rawpr = printable_ratio(head)
        seen += 1
        if pr > 0.85 and rawpr < 0.5:
            hits.append({'path': r['path'], 'size': n, 'logical': r['logical_size'],
                         'stored': r['stored_size'], 'printable': round(pr, 3),
                         'raw_printable': round(rawpr, 3),
                         'decoded_head': dec[:160].decode('latin1')})
        if seen % 5000 == 0:
            print('  ...%d records, %d hits' % (seen, len(hits)))
    print('scanned %d, hits %d' % (seen, len(hits)))
    hits.sort(key=lambda h: -h['printable'])
    json.dump(hits, open('analysis/decrypt_module_candidates.json', 'w'), indent=1)
    for h in hits[:25]:
        print('%-52s size=%-8d pr=%.2f raw=%.2f | %r' %
              (h['path'], h['size'], h['printable'], h['raw_printable'],
               h['decoded_head'][:80]))


if __name__ == '__main__':
    main()
