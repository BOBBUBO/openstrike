#!/usr/bin/env python3
"""Decode Android's APS2 packed relocation section (.rela.dyn) of libGame.so.

Format (from AOSP bionic/linker/linker_reloc_iterators.h):

    magic   "APS2"
    sleb128 num_relocs
    sleb128 first_r_offset                 (absolute)
    repeat num_relocs times (grouped):
        sleb128 group_size
        sleb128 group_flags
        if flags & GROUPED_BY_OFFSET_DELTA(2): sleb128 group_r_offset_delta
        if flags & GROUPED_BY_INFO(1):        sleb128 r_info
        if flags & HAS_ADDEND(8):
            if flags & GROUPED_BY_ADDEND(4):  sleb128 base_addend
        for each of group_size relocs:
            if flags & GROUPED_BY_OFFSET_DELTA: r_offset += group_r_offset_delta
            else:                               r_offset += sleb128 delta
            if not (flags & GROUPED_BY_INFO):   r_info = sleb128
            if flags & HAS_ADDEND:
                if not (flags & GROUPED_BY_ADDEND): r_addend += sleb128

All numbers are signed LEB128.

The result lets us resolve every relocated pointer inside .data.rel.ro and
.data, which is where Cython keeps its string-constant table, its method
definition tables (__pyx_mdef) and its interned-name tables.
"""
import json
import os
import struct
import subprocess
import sys

SO = 'decompiled/native/lib/arm64-v8a/libGame.so'
OUT = 'analysis/aps2-relocs.json'

GROUPED_BY_INFO = 1
GROUPED_BY_OFFSET_DELTA = 2
GROUPED_BY_ADDEND = 4
HAS_ADDEND = 8

R_AARCH64 = {
    0: 'NONE', 257: 'ABS64', 258: 'ABS32', 259: 'ABS16', 260: 'PREL64',
    261: 'PREL32', 262: 'PREL16', 1024: 'COPY', 1025: 'GLOB_DAT',
    1026: 'JUMP_SLOT', 1027: 'RELATIVE', 1028: 'TLS_DTPMOD64',
    1029: 'TLS_DTPREL64', 1030: 'TLS_TPREL64', 1031: 'TLSDESC',
    1032: 'IRELATIVE',
}
SHT = {0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA',
       5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL',
       11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY',
       0x6ffffff6: 'GNU_HASH', 0x6ffffffe: 'VERNEED', 0x6fffffff: 'VERSYM',
       0x70000001: 'AARCH64_RELR'}


def sleb(b, i):
    r = 0
    s = 0
    while True:
        c = b[i]
        i += 1
        r |= (c & 0x7F) << s
        s += 7
        if not (c & 0x80):
            if c & 0x40:
                r -= 1 << s
            return r, i


def elf_sections(path):
    out = subprocess.run(['readelf', '-SW', path], capture_output=True,
                         text=True).stdout
    secs = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith('['):
            continue
        # [ N] name type addr off size ...
        try:
            idx = line.index(']')
        except ValueError:
            continue
        rest = line[idx + 1:].split()
        if len(rest) < 5:
            continue
        name = rest[0]
        if name.startswith('.') or name in ('NULL',):
            pass
        try:
            typ = int(rest[1], 16)
        except ValueError:
            typ = 0
        try:
            addr = int(rest[2], 16)
            off = int(rest[3], 16)
            size = int(rest[4], 16)
        except (ValueError, IndexError):
            continue
        secs.append((name, typ, addr, off, size))
    return secs


def main():
    d = open(SO, 'rb').read()
    secs = elf_sections(SO)
    rela = next(s for s in secs if s[0] == '.rela.dyn')
    name, typ, addr, off, size = rela
    b = d[off:off + size]
    assert b[:4] == b'APS2', b[:4]
    i = 4
    num, i = sleb(b, i)
    r_offset, i = sleb(b, i)
    print('APS2: num_relocs=%d first_r_offset=0x%x' % (num, r_offset))
    relocs = []
    done = 0
    addend = 0          # persistent: AOSP accumulates r_addend across the
                        # whole section (never reset except for groups
                        # without any addend flag)
    while done < num and i < len(b):
        gsize, i = sleb(b, i)
        gflags, i = sleb(b, i)
        gdelta = 0
        r_info = 0
        if gflags & GROUPED_BY_OFFSET_DELTA:
            gdelta, i = sleb(b, i)
        if gflags & GROUPED_BY_INFO:
            r_info, i = sleb(b, i)
        gflags_reloc = gflags & (HAS_ADDEND | GROUPED_BY_ADDEND)
        if gflags_reloc == (HAS_ADDEND | GROUPED_BY_ADDEND):
            a, i = sleb(b, i)
            addend += a
        elif gflags_reloc == 0:
            addend = 0
        for _ in range(gsize):
            if gflags & GROUPED_BY_OFFSET_DELTA:
                r_offset += gdelta
            else:
                dlt, i = sleb(b, i)
                r_offset += dlt
            if not (gflags & GROUPED_BY_INFO):
                r_info, i = sleb(b, i)
            if gflags_reloc == HAS_ADDEND:
                a, i = sleb(b, i)
                addend += a
            relocs.append((r_offset, r_info, addend))
        done += gsize
    print('decoded %d relocations (consumed %d/%d bytes)'
          % (len(relocs), i, size))
    kinds = {}
    for _, info, _a in relocs:
        t = info & 0xFFFFFFFF
        kinds[R_AARCH64.get(t, t)] = kinds.get(R_AARCH64.get(t, t), 0) + 1
    print('types:', kinds)

    # ---- resolve the image ------------------------------------------------
    dynsym = next((s for s in secs if s[0] == '.dynsym'), None)
    dynstr = next((s for s in secs if s[0] == '.dynstr'), None)
    symval = {}
    if dynsym and dynstr:
        _n, _t, _a, soff, ssize = dynsym
        strtab = d[dynstr[3]:dynstr[3] + dynstr[4]]
        n = ssize // 24
        for k in range(n):
            base = soff + k * 24
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from('<IBBHQQ', d, base)
            end = strtab.find(b'\0', st_name)
            nm = strtab[st_name:end].decode('latin1')
            symval[k] = (st_value, st_shndx, nm)
    img = bytearray(d)
    unresolved = 0
    for off_, info, add in relocs:
        if off_ + 8 > len(img):
            continue
        typ = info & 0xFFFFFFFF
        sym = info >> 32
        if typ == 1027:                       # R_AARCH64_RELATIVE
            val = add & 0xFFFFFFFFFFFFFFFF
        elif typ in (257, 1025, 1026):        # ABS64 / GLOB_DAT / JUMP_SLOT
            sv, shndx, nm = symval.get(sym, (0, 0, ''))
            if shndx == 0:                    # SHN_UNDEF -> import
                unresolved += 1
                continue
            val = (sv + add) & 0xFFFFFFFFFFFFFFFF
        else:
            continue
        struct.pack_into('<Q', img, off_, val)
    print('unresolved (import) ABS64 entries:', unresolved)
    outp = 'analysis/libGame.relocated.so'
    open(outp, 'wb').write(img)
    print('wrote', outp, len(img))

    # index: vaddr -> (section, file offset)
    secidx = []
    for n, t, a, o, sz in secs:
        if n in ('NULL',):
            continue
        secidx.append((n, a, o, sz))
    def where(v):
        for n, a, o, sz in secidx:
            if a <= v < a + sz:
                return n
        return '?'

    json.dump([{'off': o, 'type': R_AARCH64.get(i & 0xFFFFFFFF,
                                                i & 0xFFFFFFFF),
                'info': i, 'add': a, 'sec': where(o)}
               for o, i, a in relocs], open(OUT, 'w'))
    print('wrote', OUT)


if __name__ == '__main__':
    main()
