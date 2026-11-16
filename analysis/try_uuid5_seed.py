#!/usr/bin/env python3
"""Brute-force the UUIDv5 namespace used by the engine's encrypted-module file
names.

Known data points:
  LocalData/Patch/0a/0a0ab8a4-df96-4d5-9a862-967c2adca6f
  LocalData/Patch/0d/0d0ab9a4-df96-4d5-9a862-967c2adca6f
      -> RFC-4122 **v5** (name-based SHA-1) UUIDs, differing in one bit.
  LocalData/Patch/UIScript/4051BDD0000f042.pyo
      -> 16 hex chars (8 bytes) whose content is the plain UUID
         71ad02b5-a3ec-4ec4-9c89-3b0979779444.

The script tries every candidate logical name against
  * the four RFC-4122 standard namespaces
  * the two seed UUIDs themselves used as a namespace
and reports any uuid5() whose first 8 bytes match the .pyo name, or whose full
value matches one of the seed UUIDs.
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

SEED_UUIDS = ['0ab8a4df-964d-5d9a-8629-67c2adca6f',
              '0ab9a4df-964d-5d9a-8629-67c2adca6f']
PYO_PREFIX = '4051bdd0000f042'
DASHV5 = re.compile(
    r'^[0-9a-f]{2}/([0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-'
    r'[89ab][0-9a-f]{3}-[0-9a-f]{12})$')


def main():
    rows = [json.loads(l) for l in open(TABLE)]
    v5set = set()
    for x in rows:
        m = DASHV5.match(x.get('name') or '')
        if m:
            v5set.add(m.group(1))

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
    for nm in ('UIScript/%s' % s for s in SEED_UUIDS):
        cands.add(nm)
    cands.add('Script/Python/MConfig.py')
    cands.discard('')
    print('candidate names :', len(cands))
    print('package v5 uuids :', len(v5set))

    namespaces = {'dns': uuid.NAMESPACE_DNS, 'url': uuid.NAMESPACE_URL,
                  'oid': uuid.NAMESPACE_OID, 'x500': uuid.NAMESPACE_X500}
    for s in SEED_UUIDS:
        namespaces['seed:' + s[:8]] = uuid.UUID(s)

    hit_seed, hit_pyo, hit_v5 = [], [], []
    for nm in cands:
        b = nm.encode()
        for k, ns in namespaces.items():
            d = hashlib.sha1(ns.bytes + b).digest()[:16]
            u = uuid.UUID(bytes=d, version=5)
            if str(u) in SEED_UUIDS:
                hit_seed.append((nm, k, str(u)))
            if d.hex()[:16] == PYO_PREFIX:
                hit_pyo.append((nm, k, d.hex()))
            if str(u) in v5set:
                hit_v5.append((nm, k, str(u)))
        if len(hit_seed) > 5 or len(hit_pyo) > 5 or len(hit_v5) > 5:
            break
    print('uuid5 == seed uuid     :', len(hit_seed), hit_seed[:5])
    print('uuid5[:8] == .pyo name :', len(hit_pyo), hit_pyo[:5])
    print('uuid5 == package v5    :', len(hit_v5), hit_v5[:5])


if __name__ == '__main__':
    main()
