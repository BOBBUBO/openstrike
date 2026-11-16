#!/usr/bin/env python3
"""Test whether the undashed 32-hex package names are raw SHA-1 (UUIDv5 without
the version/variant bits) of a known logical name under one of the four RFC-4122
standard namespaces, and whether the dashed v5 UUIDs are genuine uuid5() values.

Result (see FINDINGS §2.5): both negative — the engine uses a private
namespace and/or a non-standard digest, so the name hash must be recovered
from code rather than guessed.
"""
import hashlib
import json
import os
import re
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PATCHLIST = os.path.join(
    ROOT, 'stock-files/com.netease.newspike/files/LocalData/Patch/'
          'spike_patchlist_android_astc_512_py3.txt')
TABLE = os.path.join(HERE, 'package-file-table2.jsonl')

UND = re.compile(r'^[0-9a-f]{2}/([0-9a-f]{32})$')
DASHV5 = re.compile(
    r'^[0-9a-f]{2}/([0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-'
    r'[89ab][0-9a-f]{3}-[0-9a-f]{12})$')


def main():
    rows = [json.loads(l) for l in open(TABLE)]
    undset, v5set = set(), set()
    for x in rows:
        n = x.get('name') or ''
        m = UND.match(n)
        if m:
            undset.add(m.group(1))
        m = DASHV5.match(n)
        if m:
            v5set.add(m.group(1))
    print('undashed names :', len(undset))
    print('dashed v5 names:', len(v5set))

    cands = set()
    pl = json.load(open(PATCHLIST))
    for sec, dd in pl.items():
        if isinstance(dd, dict):
            cands.update(dd.keys())
        elif isinstance(dd, list):
            for it in dd:
                if isinstance(it, str):
                    cands.add(it)
    cands.update((x.get('name') or '') for x in rows)
    cands.discard('')
    print('candidate names:', len(cands))

    ns = {'dns': uuid.NAMESPACE_DNS, 'url': uuid.NAMESPACE_URL,
          'oid': uuid.NAMESPACE_OID, 'x500': uuid.NAMESPACE_X500}
    hits5, hitu = [], []
    for nm in cands:
        b = nm.encode()
        for k, n in ns.items():
            d = hashlib.sha1(n.bytes + b).digest()[:16]
            h = d.hex()
            if h in undset:
                hitu.append((nm, k, 'sha1raw', h))
            u5 = str(uuid.UUID(bytes=d, version=5))
            if u5 in v5set:
                hits5.append((nm, k, 'uuid5', u5))
        if len(hitu) > 10 and len(hits5) > 10:
            break
    print('uuid5 matches      :', len(hits5), hits5[:5])
    print('raw sha1[:16] hits :', len(hitu), hitu[:5])


if __name__ == '__main__':
    main()
