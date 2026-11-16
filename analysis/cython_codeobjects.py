#!/usr/bin/env python3
"""Recover the Cython code objects (co_consts / co_names / co_varnames) of the
four Cython modules embedded in libGame.so.

With the APS2 relocations applied, every pointer in .data.rel.ro is a real
address.  A Cython function is backed by a static CPython `PyCodeObject`:

    struct PyCodeObject {          (CPython 3.11/3.12 layout)
        PyObject_HEAD;              //  0
        int co_argcount;            // 16
        int co_posonlyargcount;     // 20
        int co_kwonlyargcount;      // 24
        int co_nlocals;             // 28
        int co_stacksize;           // 32
        int co_flags;               // 36
        int co_firstlineno;         // 40
        PyObject *co_code;          // 48
        PyObject *co_consts;        // 56
        PyObject *co_names;         // 64
        PyObject *co_varnames;      // 72
        ...
    };

This script locates every tuple of interned strings (i.e. co_names /
co_varnames), finds the code object that owns it, and dumps the function's
source-level identifiers and constants.  This is the fastest route to the
*Python* source of `MImporter.decrypt_string`.
"""
import json
import os
import re
import struct
import sys
from collections import defaultdict

SO = 'analysis/libGame.relocated.so'
OUT = 'analysis/cython-codeobjects.json'
DATA_RANGES = ((0x5d157c0, 0x64b7580), (0x64bb580, 0x715e280))
STR_MAX = 0x71570e8


def cstr(d, v, maxlen=200):
    if not (0 < v < STR_MAX):
        return None
    e = d.find(b'\0', v, v + maxlen)
    if e < 0:
        return None
    try:
        s = d[v:e].decode('utf-8')
    except UnicodeDecodeError:
        return None
    if not s or not re.fullmatch(r'[\x20-\x7e]+', s):
        return None
    return s


def is_tuple(d, t, tuple_types):
    if t + 24 > len(d):
        return None
    typ = struct.unpack_from('<Q', d, t + 8)[0]
    if typ not in tuple_types:
        return None
    n = struct.unpack_from('<q', d, t + 16)[0]
    if n < 0 or n > 64:
        return None
    items = []
    for i in range(n):
        p = struct.unpack_from('<Q', d, t + 24 + 8 * i)[0]
        items.append(p)
    return items


def main():
    d = open(SO, 'rb').read()
    n = len(d)

    # --- find tuple type objects -----------------------------------------
    cand = defaultdict(int)
    ptrs = []
    for lo, hi in DATA_RANGES:
        hi = min(hi, n)
        for slot in range(lo, hi - 8, 8):
            p = struct.unpack_from('<Q', d, slot)[0]
            if not (0 < p < n - 24):
                continue
            sz = struct.unpack_from('<q', d, p + 16)[0]
            if 0 <= sz <= 64:
                typ = struct.unpack_from('<Q', d, p + 8)[0]
                cand[typ] += 1
    tuple_types = {t for t, c in cand.items() if c > 20}
    print('candidate tuple type objects:', len(tuple_types))

    # --- collect all tuples of strings ------------------------------------
    tuples = {}
    for lo, hi in DATA_RANGES:
        hi = min(hi, n)
        for slot in range(lo, hi - 8, 8):
            p = struct.unpack_from('<Q', d, slot)[0]
            if not (0 < p < n - 24):
                continue
            it = is_tuple(d, p, tuple_types)
            if it is None or not it:
                continue
            strs = [cstr(d, x) for x in it]
            if all(s for s in strs):
                tuples[p] = strs
    print('tuples of strings:', len(tuples))

    # --- find code objects referencing them -------------------------------
    codes = {}
    for lo, hi in DATA_RANGES:
        hi = min(hi, n)
        for slot in range(lo, hi - 8, 8):
            p = struct.unpack_from('<Q', d, slot)[0]
            if not (0 < p < n - 96):
                continue
            # slot is a pointer to a PyCodeObject if slot+56/64/72 points at a
            # tuple of strings
            for field, off in (('consts', 56), ('names', 64),
                               ('varnames', 72)):
                t = struct.unpack_from('<Q', d, p + off)[0]
                if t in tuples:
                    co = codes.setdefault(p, {})
                    co[field] = tuples[t]
    print('code objects found:', len(codes))

    def cconsts(co):
        # co_consts tuple: pull ints and strings
        for lo, hi in DATA_RANGES:
            pass
        return None

    out = []
    for p, co in sorted(codes.items()):
        names = co.get('names') or []
        varn = co.get('varnames') or []
        interesting = any(k in names + varn for k in
                          ('decrypt', 'salt', 'sdata', 'key', 'cdata',
                           'datalen', 'head', 'comps', 'index'))
        if not interesting and len(varn) < 2:
            continue
        # co_firstlineno
        flin = struct.unpack_from('<i', d, p + 40)[0]
        nloc = struct.unpack_from('<i', d, p + 28)[0]
        out.append({'code': p, 'firstlineno': flin, 'nlocals': nloc,
                    'names': names, 'varnames': varn,
                    'consts': co.get('consts')})
    print('interesting code objects:', len(out))
    for c in out[:40]:
        print('\n-- code @0x%x line=%s nlocals=%d' %
              (c['code'], c['firstlineno'], c['nlocals']))
        print('   varnames:', c['varnames'])
        print('   names   :', c['names'][:30])
        if c['consts']:
            print('   consts  :', c['consts'][:20])
    json.dump(out, open(OUT, 'w'), indent=1)
    print('\nwrote', OUT)


if __name__ == '__main__':
    main()
