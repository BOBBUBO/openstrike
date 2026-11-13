#!/usr/bin/env python3
"""Build a reverse-pointer index for libGame.so.

.rela.dyn is packed (APS2 blob) so normal reloc-based xrefs are impossible.
But the *contents* of .data.rel.ro / .data / .got are still plain data in the
file and contain many absolute pointers (const char* tables, vtables, ...).
This script scans every readable section for 8-byte little-endian values that
look like in-image pointers and records where each pointer value occurs.

Usage:
  python3 analysis/ptr_index.py build analysis/ptr-index.json
  python3 analysis/ptr_index.py find 0x5ada2f      # who points at this addr
"""
import json
import os
import struct
import sys

ELF = 'decompiled/native/lib/arm64-v8a/libGame.so'


def read_elf_sections(data):
    """Minimal ELF64 section-header parser -> list of dicts."""
    assert data[:4] == b'\x7fELF'
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, stype, flags, addr, offset, size, link, info, align, entsize = \
            struct.unpack_from('<IIQQQQIIQQ', data, off)
        secs.append(dict(name_off=name, type=stype, flags=flags, addr=addr,
                         offset=offset, size=size, entsize=entsize))
    strtab = secs[e_shstrndx]
    for s in secs:
        nm = data[strtab['offset'] + s['name_off']:
                  data.index(b'\0', strtab['offset'] + s['name_off'])]
        s['name'] = nm.decode()
    return secs


def build():
    data = open(ELF, 'rb').read()
    secs = read_elf_sections(data)
    lo = min(s['addr'] for s in secs if s['addr'])
    hi = max(s['addr'] + s['size'] for s in secs if s['addr'])
    # only consider pointers into allocated, file-backed sections
    file_backed = [(s['addr'], s['addr'] + s['size']) for s in secs
                   if s['type'] != 8 and s['size'] and s['addr']]  # 8 = SHT_NOBITS
    index = {}
    nptr = 0
    for s in secs:
        if s['type'] == 8 or not s['size'] or not s['addr']:
            continue
        if s['name'] not in ('.data.rel.ro', '.data', '.got', '.got.plt',
                             '.init_array', '.fini_array', '.rodata',
                             '.PyRuntime', '.eh_frame_hdr'):
            continue
        blob = data[s['offset']:s['offset'] + s['size']]
        for i in range(0, len(blob) - 7, 8):
            v = struct.unpack_from('<Q', blob, i)[0]
            if not (lo <= v < hi):
                continue
            # must land inside a file-backed section
            if not any(a <= v < b for a, b in file_backed):
                continue
            index.setdefault(v, []).append(s['addr'] + i)
            nptr += 1
    print('indexed %d pointer slots -> %d distinct targets' % (nptr, len(index)),
          file=sys.stderr)
    out = {hex(k): v for k, v in index.items()}
    with open(sys.argv[2], 'w') as f:
        json.dump(out, f)


def find():
    data = open(ELF, 'rb').read()
    secs = read_elf_sections(data)
    idx = json.load(open(sys.argv[2]))
    inv = {}
    for k, v in idx.items():
        for loc in v:
            inv.setdefault(loc, []).append(int(k, 16))
    for a in sys.argv[3:]:
        tgt = int(a, 0)
        locs = idx.get(hex(tgt), [])
        print('target 0x%x referenced from %d location(s):' % (tgt, len(locs)))
        for loc in locs[:40]:
            sec = next((s['name'] for s in secs
                        if s['addr'] <= loc < s['addr'] + s['size']), '?')
            print('   0x%x (%s)' % (loc, sec))


if __name__ == '__main__':
    if sys.argv[1] == 'build':
        build()
    else:
        find()
