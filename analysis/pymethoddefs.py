#!/usr/bin/env python3
"""Harvest Cython / CPython PyMethodDef tables from the relocated libGame.so.

After applying the APS2 packed relocations every pointer in the writable
data is resolved.  A CPython `PyMethodDef` looks like

    struct PyMethodDef {
        const char *ml_name;   -> .rodata C string
        PyCFunction ml_meth;   -> .text address
        int          ml_flags;
        const char *ml_doc;    -> .rodata C string or NULL
    };

so a run of [rodata_ptr][text_ptr][flags][doc_ptr] is a method table.
This script finds every such run and prints name -> C function address.
"""
import json
import os
import re
import struct
import sys

SO = 'analysis/libGame.relocated.so'
OUT = 'analysis/pymethoddefs.json'

RODATA = (0x588b00, 0x71570e8)   # Cython puts its string constants in .data
TEXT = (0x1dc0420, 0x5d008b4)
DATA_RANGES = ((0x5d157c0, 0x64b7580), (0x64bb580, 0x715e280))


def cstr(d, v, maxlen=160):
    if not (RODATA[0] <= v < RODATA[1]):
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


def main():
    d = open(SO, 'rb').read()
    n = len(d)
    tables = []
    for lo, hi in DATA_RANGES:
        hi = min(hi, n)
        slot = lo
        while slot + 32 <= hi:
            p = struct.unpack_from('<Q', d, slot)[0]
            m = struct.unpack_from('<Q', d, slot + 8)[0]
            if not (RODATA[0] <= p < RODATA[1]):
                slot += 8
                continue
            if not (TEXT[0] <= m < TEXT[1]):
                slot += 8
                continue
            name = cstr(d, p)
            if not name:
                slot += 8
                continue
            flags = struct.unpack_from('<I', d, slot + 16)[0]
            docp = struct.unpack_from('<Q', d, slot + 24)[0]
            doc = cstr(d, docp) if docp else None
            tables.append({'table': slot, 'name': name, 'meth': m,
                           'flags': flags, 'doc': doc})
            slot += 32
    # group by contiguous table
    groups = []
    for t in tables:
        if groups and t['table'] == groups[-1][-1]['table'] + 32:
            groups[-1].append(t)
        else:
            groups.append([t])
    print('method-def candidates: %d in %d tables'
          % (len(tables), len(groups)))
    for g in groups:
        if len(g) < 3:
            continue
        print('\n== table @0x%x (%d entries) ==' % (g[0]['table'], len(g)))
        for t in g:
            print('   %-38s 0x%x flags=%d' % (t['name'], t['meth'], t['flags']))
    json.dump(groups, open(OUT, 'w'), indent=1)
    print('\nwrote', OUT)


if __name__ == '__main__':
    main()
