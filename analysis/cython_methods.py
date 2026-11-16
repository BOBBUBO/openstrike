#!/usr/bin/env python3
"""Resolve Cython's PyMethodDef tables in the relocated libGame.so.

Now that the APS2 packed relocations have been applied, every relocated
pointer inside .data.rel.ro / .data can be dereferenced.  Cython emits one
`PyMethodDef` array per Python-visible function:

    struct PyMethodDef {
        const char *ml_name;     -> C string in .rodata
        PyCFunction ml_meth;     -> code address in .text
        int ml_flags;
        const char *ml_doc;
    };

This script scans the writable data for that signature and prints a
name -> C function address table, which is the map we need to jump
straight to the implementation of `MImporter.decrypt_string`.
"""
import json
import os
import re
import struct
import sys

SO = 'analysis/libGame.relocated.so'
OUT = 'analysis/cython-methods.json'

# section layout (from readelf)
RODATA = (0x588b00, 0x5d117a0)
TEXT = (0x1dc0420, 0x5d008b4)
DATA_RANGES = ((0x5d157c0, 0x64b7580), (0x64bb580, 0x715e280))


def cstr(d, v, maxlen=200):
    if not (RODATA[0] <= v < RODATA[1]):
        return None
    e = d.find(b'\0', v, v + maxlen)
    if e < 0:
        return None
    b = d[v:e]
    if not b or len(b) > 120:
        return None
    try:
        s = b.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if not re.fullmatch(r'[\x20-\x7e]*', s):
        return None
    return s


def main():
    d = open(SO, 'rb').read()
    found = {}
    for lo, hi in DATA_RANGES:
        for slot in range(lo, min(hi, len(d)) - 32, 8):
            p = struct.unpack_from('<Q', d, slot)[0]
            if not (RODATA[0] <= p < RODATA[1]):
                continue
            name = cstr(d, p)
            if not name:
                continue
            meth = struct.unpack_from('<Q', d, slot + 8)[0]
            if not (TEXT[0] <= meth < TEXT[1]):
                continue
            flags = struct.unpack_from('<I', d, slot + 16)[0]
            docp = struct.unpack_from('<Q', d, slot + 24)[0]
            doc = cstr(d, docp) if docp else None
            found.setdefault(name, []).append(
                {'slot': slot, 'meth': meth, 'flags': flags, 'doc': doc})
    print('PyMethodDef-like entries: %d unique names' % len(found))
    keys = [k for k in found if 'decrypt' in k or 'encrypt' in k or
            'md5' in k or 'importer' in k.lower() or 'gen_' in k]
    for k in sorted(keys):
        for e in found[k]:
            print('  %-34s meth=0x%x flags=%d doc=%r'
                  % (k, e['meth'], e['flags'], (e['doc'] or '')[:40]))
    json.dump(found, open(OUT, 'w'), indent=1)
    print('wrote', OUT)


if __name__ == '__main__':
    main()
