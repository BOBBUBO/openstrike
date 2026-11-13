#!/usr/bin/env python3
"""Locate the frozen-module table (name -> marshalled code object) inside
libGame.so.

CPython/Jython keep built-in pure-Python modules as a static array of
    { const char *name; PyObject *(*loader)(void); ... }
or, for the "frozen" importer, a table of
    { const char *name; _PyCodeObject *code; }
We scan the writable data sections for 16-byte slots where the first pointer
lands on a NUL-terminated string that looks like a Python module name and the
second pointer lands inside the image.
"""
import json
import re
import struct
import sys

ELF = 'decompiled/native/lib/arm64-v8a/libGame.so'
data = open(ELF, 'rb').read()
IDX = json.load(open('analysis/ptr-index.json'))

MODNAME = re.compile(rb'^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$')


def cstr_at(off, maxlen=80):
    try:
        e = data.index(b'\0', off)
    except ValueError:
        return None
    s = data[off:e]
    if len(s) > maxlen:
        return None
    return s


def main():
    # find candidate name strings in .rodata
    hits = []
    for ptr_hex, locs in IDX.items():
        ptr = int(ptr_hex, 16)
        if not (0x588b00 <= ptr < 0xe90cb0):   # .rodata
            continue
        s = cstr_at(ptr)
        if not s or not MODNAME.match(s):
            continue
        if len(s) < 3:
            continue
        # require the pointer to be the *start* of the string
        if ptr > 0 and data[ptr - 1] != 0:
            continue
        hits.append((ptr, s.decode(), locs))
    print('candidate module-name strings referenced from data: %d' % len(hits))
    # look for a table: several name pointers within a small window
    byloc = []
    for ptr, name, locs in hits:
        for loc in locs:
            byloc.append((loc, ptr, name))
    byloc.sort()
    print('%-12s %-34s %s' % ('table@', 'name', 'neighbours'))
    i = 0
    while i < len(byloc):
        j = i
        while j + 1 < len(byloc) and byloc[j + 1][0] - byloc[j][0] <= 24:
            j += 1
        if j - i >= 5:
            loc = byloc[i][0]
            names = [n for _, _, n in byloc[i:j + 1]]
            print('0x%-9x %d entries: %s' % (loc, len(names), names[:12]))
        i = j + 1


if __name__ == '__main__':
    main()
