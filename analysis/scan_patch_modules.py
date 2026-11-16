#!/usr/bin/env python3
"""
Scan every GUID-named record in the patch archives (Patch.mpk .. Patch7.mpk)
for an encrypted Python module, using the FINAL MImporter.decrypt_string model:

    r   = (len(data) - 8) % 37
    v   = data[0 : 128 - r]
    out = bytearray(v)
    out[i] ^= 154

Oracle: the decoded head must contain >= 2 Python source tokens, or start with
a recognised container magic (zlib / gzip / marshal).  A printable-ratio test
alone is NOT used (it produced 1,537 false positives under the refuted model).

Also reports the head of every record whose first bytes look like a *known*
encrypted-module header, plus the distribution of decoded-head shapes so the
container format can be inferred statistically.
"""
import collections
import json
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mpk_extract  # noqa: E402

PY_TOKENS = (b'import ', b'def ', b'class ', b'from ', b'print(', b'__name__',
             b'if __', b'# -*-', b'"""', b"'''", b'return ', b'lambda ',
             b'@decorator', b'global ', b'elif ', b'while ', b'True', b'None',
             b'raise ', b'with ', b'yield ', b'async ', b'self.', b'os.',
             b'sys.', b'if ', b'for ')

MAGICS = {
    b'\x78\x9c': 'zlib-default',
    b'\x78\x01': 'zlib-low',
    b'\x78\xda': 'zlib-best',
    b'\x1f\x8b': 'gzip',
    b'\x28\xb5\x2f\xfd': 'zstd',
    b'PK\x03\x04': 'zip',
    b'\xe3\x00\x00\x00': 'marshal-3.12',
    b'\x63\x00\x00\x00': 'marshal-3.8',
    b'\x42\x0d\x0d\x0a': 'pyc-3.7+',
    b'\x55\x0d\x0d\x0a': 'pyc-3.9+',
}


def decrypt_head(data):
    n = len(data)
    r = (n - 8) % 37
    stop = 128 - r
    v = data[0:stop]
    out = bytearray(v)
    for i in range(len(out)):
        out[i] ^= 154
    return bytes(out), r, stop


def classify(head):
    if head[:2] in MAGICS:
        return 'magic:' + MAGICS[head[:2]]
    if head[:4] in MAGICS:
        return 'magic:' + MAGICS[head[:4]]
    hits = sum(1 for t in PY_TOKENS if t in head)
    if hits >= 2:
        return 'python-tokens:%d' % hits
    return None


def main():
    recs = [json.loads(l) for l in open('analysis/patch-records.jsonl')]
    print('records: %d' % len(recs))
    amap = mpk_extract.ArchiveMap('stock-files/com.netease.newspike/files/LocalData/Patch')
    handles = {}
    hits = []
    shapes = collections.Counter()
    kinds = collections.Counter()
    n_decoded = 0
    for idx, r in enumerate(recs):
        arc = r.get('archive')
        ao = r.get('archive_offset')
        sz = r.get('stored_size')
        if arc is None or ao is None:
            continue
        fh = handles.get(arc)
        if fh is None:
            fh = open(arc, 'rb')
            handles[arc] = fh
        fh.seek(ao)
        raw = fh.read(sz or 65536)
        try:
            payload, kind, det = mpk_extract.decode_entry(raw)
        except Exception:
            kinds['decode-error'] += 1
            continue
        kinds[kind] += 1
        n_decoded += 1
        head, rr, stop = decrypt_head(payload)
        c = classify(head)
        if c:
            hits.append({'path': r.get('path'), 'archive': os.path.basename(arc),
                         'kind': kind, 'size': len(payload), 'r': rr, 'stop': stop,
                         'class': c, 'head_hex': head[:64].hex(),
                         'head_repr': repr(head[:96])})
        shapes[head[:4].hex()] += 1
        if (idx + 1) % 10000 == 0:
            print('  ... %d/%d decoded, hits=%d' % (idx + 1, len(recs), len(hits)))
    for fh in handles.values():
        fh.close()
    print('decoded: %d  kinds: %s' % (n_decoded, dict(kinds)))
    print('hits: %d' % len(hits))
    for h in hits[:60]:
        print('  %-46s %-16s %-20s %s' % (h['path'][:46], h['kind'], h['class'],
                                           h['head_repr'][:60]))
    with open('analysis/patch-encrypted-module-hits.json', 'w') as f:
        json.dump(hits, f, indent=1)
    with open('analysis/patch-decoded-head-shapes.json', 'w') as f:
        json.dump(shapes.most_common(200), f, indent=1)
    print('top decoded-head prefixes:')
    for k, v in shapes.most_common(15):
        print('   %s  %d' % (k, v))


if __name__ == '__main__':
    main()
