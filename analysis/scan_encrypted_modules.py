#!/usr/bin/env python3
"""
Scan every GUID-named asset in the patch archives and the Android package for
material that decrypts to a Python module under the *final* MImporter
.decrypt_string model:

    r   = (len(data) - 8) % 37
    v   = data[0 : 128 - r]
    out = bytearray(v)
    out[i] ^= 154

Oracle (deliberately strict, to kill the false positives produced by the
earlier, refuted "stride = step+1" model):

  * the decoded head must contain at least one *diverse* printable run,
  * character-class entropy must be above a floor, and
  * the decoded head must not be a repetition of a single byte.

Also tries the "whole-file XOR-154" variant, in case the module body is
encrypted with a plain XOR pass rather than the header-only routine.
"""
import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mimporter_decrypt import decrypt_string  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mpk_extract  # noqa: E402

PY_TOKENS = (b'import ', b'def ', b'class ', b'from ', b'print(', b'__name__',
             b'if __', b'# -*-', b'"""', b"'''", b'@', b'return ', b'lambda ')


def diversity(b):
    """Fraction of distinct byte values, weighted by class variety."""
    if not b:
        return 0.0, 0.0
    distinct = len(set(b)) / 256.0
    classes = 0
    for test in (lambda c: 97 <= c <= 122, lambda c: 65 <= c <= 90,
                 lambda c: 48 <= c <= 57,
                 lambda c: c in b' \t\r\n',
                 lambda c: c in b'(){}[]:;,.=+-*/<>!@#$%^&_|~'):
        if any(test(c) for c in b):
            classes += 1
    return distinct, classes / 6.0


def py_like(b):
    """Does the buffer look like source code / a code object?"""
    hits = sum(1 for t in PY_TOKENS if t in b)
    if hits >= 2:
        return True
    # a marshalled code object starts with a known magic
    if b[:4] in (b'\xe3\x00\x00\x00', b'\x63\x00\x00\x00'):
        return True
    if b[:2] == b'\x78\x9c' or b[:2] == b'\x78\x01':
        return True
    return False


def score(b):
    d, c = diversity(b)
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / max(1, len(b))
    return printable, d, c


def test_blob(raw, name, source, out):
    if not raw:
        return
    n = len(raw)
    r = (n - 8) % 37
    stop = 128 - r
    head = bytes(decrypt_string(raw))
    printable, distinct, classes = score(head)
    interesting = (printable > 0.80 and distinct > 0.10 and classes > 0.45) or \
                  py_like(head)
    if interesting:
        out.append({
            "name": name, "source": source, "mode": "decrypt_string",
            "size": n, "r": r, "stop": stop,
            "printable": round(printable, 3), "distinct": round(distinct, 3),
            "classes": round(classes, 3),
            "head_hex": head[:64].hex(),
            "head_repr": repr(head[:96]),
        })
        return
    # whole-file XOR-154
    if n <= 2 * 1024 * 1024:
        full = bytes(x ^ 154 for x in raw)
        printable, distinct, classes = score(full[:2048])
        if (printable > 0.85 and distinct > 0.12 and classes > 0.5) or py_like(full):
            out.append({
                "name": name, "source": source, "mode": "xor154-whole",
                "size": n, "printable": round(printable, 3),
                "distinct": round(distinct, 3), "classes": round(classes, 3),
                "head_hex": full[:64].hex(),
                "head_repr": repr(full[:96]),
            })


def scan_package(out):
    path = 'analysis/package-file-table.jsonl'
    if not os.path.exists(path):
        return 0
    n = 0
    with open(path) as f:
        for line in f:
            r = json.loads(line)
            name = r.get('name') or ''
            if not name:
                continue
            # only the encrypted namespace (UUID-ish names)
            if name.count('-') < 4:
                continue
            n += 1
            try:
                raw = load_package_blob(r)
            except Exception:
                continue
            if raw is None:
                continue
            test_blob(raw, name, 'package', out)
    return n


def load_package_blob(r):
    cont = r.get('container')
    off = r.get('offset')
    if off is None:
        return None
    if cont == 'Resources1.mpk':
        p = 'decompiled/apk/split_base_mpk/assets/Resources1.mpk'
        with open(p, 'rb') as f:
            f.seek(off)
            return f.read(r.get('size') or 65536)
    if cont == 'Resources.mpk':
        p = 'decompiled/apk/split_base_mpk/assets/Resources.mpk'
        with open(p, 'rb') as f:
            f.seek(off)
            raw = f.read(0x40 + (r.get('size') or 0))
        try:
            payload, kind, _ = mpk_extract.decode_entry(raw)
            return payload
        except Exception:
            return None
    return None


def scan_patch(out):
    path = 'analysis/patch-records.jsonl'
    if not os.path.exists(path):
        return 0
    amap = mpk_extract.ArchiveMap('stock-files/com.netease.newspike/files/LocalData/Patch')
    n = 0
    handles = {}
    with open(path) as f:
        for line in f:
            r = json.loads(line)
            name = r.get('path') or ''
            if not name:
                continue
            n += 1
            arc = r.get('archive')
            ao = r.get('archive_offset')
            sz = r.get('stored_size')
            if arc is None or ao is None:
                continue
            fh = handles.get(arc)
            if fh is None:
                try:
                    fh = open(arc, 'rb')
                except OSError:
                    continue
                handles[arc] = fh
            try:
                fh.seek(ao)
                raw = fh.read(sz or 65536)
            except OSError:
                continue
            try:
                payload, kind, _ = mpk_extract.decode_entry(raw)
            except Exception:
                continue
            test_blob(payload, name, 'patch:' + os.path.basename(arc), out)
    for fh in handles.values():
        fh.close()
    return n


def main():
    out = []
    which = sys.argv[1] if len(sys.argv) > 1 else 'all'
    if which in ('all', 'package'):
        n = scan_package(out)
        print('package GUID entries scanned: %d' % n)
    if which in ('all', 'patch'):
        n = scan_patch(out)
        print('patch records scanned: %d' % n)
    print('hits: %d' % len(out))
    bysrc = collections.Counter((o['source'], o['mode']) for o in out)
    for k, v in bysrc.most_common():
        print('   %-28s %-14s %d' % (k[0], k[1], v))
    with open('analysis/decrypt_module_candidates2.json', 'w') as f:
        json.dump(out, f, indent=1)
    for o in out[:40]:
        print('  %-46s %-14s size=%-8d %s' % (o['name'][:46], o['mode'],
                                              o['size'], o.get('head_repr', '')[:70]))


if __name__ == '__main__':
    main()
