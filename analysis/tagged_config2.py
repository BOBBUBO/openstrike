#!/usr/bin/env python3
"""Parser for the NetEase/Messiah *tagged binary* config format.

Two flavours exist:

 1. the "named entry" flavour used by TroyConfig/*.bin and LocalData/Config*:

        file  := magic[4] md5[16] entry*
        entry := u16le name_len | name | tag | value
        value := 's' u32le n | n * entry            (sub-map)
               | 'p' u32le n | n * u8               (byte blob / pointer table)
               | 'v' u32le n | n * value            (vector of tagged values)
               | 'M' u32le n | n * value            (map of tagged values)
               | 'i' u32le v                         (int)

 2. the "flat dict" flavour used by essential_py3:

        file  := '{' value* '}'   with value := 's'|'i'|'('|'{' ...

The first four bytes of flavour-1 files look like a per-file checksum (they
differ for every file even though the rest of the grammar is identical).
"""
import struct
import sys


class ParseError(Exception):
    pass


def u16(b, p):
    return struct.unpack_from('<H', b, p)[0], p + 2


def u32(b, p):
    return struct.unpack_from('<I', b, p)[0], p + 4


def parse_value(buf, pos, depth=0):
    if pos >= len(buf):
        raise ParseError('eof at %d' % pos)
    tag = buf[pos:pos + 1]
    pos += 1
    if tag == b's':
        n, pos = u32(buf, pos)
        return parse_entries(buf, pos, n, depth + 1)
    if tag == b'p':
        n, pos = u32(buf, pos)
        if pos + n > len(buf):
            raise ParseError('blob overrun')
        return buf[pos:pos + n], pos + n
    if tag in (b'v', b'M'):
        n, pos = u32(buf, pos)
        items = []
        for _ in range(n):
            v, pos = parse_value(buf, pos, depth + 1)
            items.append(v)
        return items, pos
    if tag == b'i':
        return u32(buf, pos)
    if tag == b'(':
        n, pos = u32(buf, pos)
        items = []
        for _ in range(n):
            v, pos = parse_value(buf, pos, depth + 1)
            items.append(v)
        return items, pos
    if tag == b'{':
        items = []
        while pos < len(buf) and buf[pos:pos + 1] != b'}':
            v, pos = parse_value(buf, pos, depth + 1)
            items.append(v)
        if pos >= len(buf):
            raise ParseError('unterminated dict')
        return items, pos + 1
    raise ParseError('unknown tag %r at %d' % (tag, pos - 1))


def parse_entries(buf, pos, count, depth=0):
    out = []
    for _ in range(count):
        nlen, pos = u16(buf, pos)
        name = buf[pos:pos + nlen]
        if len(name) != nlen:
            raise ParseError('short name')
        pos += nlen
        val, pos = parse_value(buf, pos, depth)
        out.append((name.decode('utf-8', 'replace'), val))
    return out, pos


def parse_file(buf, header=20):
    """Parse a named-entry config file; return (entries, end_offset)."""
    pos = header
    out = []
    while pos < len(buf):
        nlen, pos = u16(buf, pos)
        name = buf[pos:pos + nlen]
        if len(name) != nlen:
            raise ParseError('short name at %d' % pos)
        pos += nlen
        val, pos = parse_value(buf, pos)
        out.append((name.decode('utf-8', 'replace'), val))
    return out, pos


if __name__ == '__main__':
    path = sys.argv[1]
    hdr = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    buf = open(path, 'rb').read()
    try:
        items, end = parse_file(buf, hdr)
        print('OK %s: %d entries, consumed %d / %d' %
              (path, len(items), end, len(buf)))
        for nm, v in items[:6]:
            print('   %-28s %r' % (nm, str(v)[:90]))
    except Exception as e:
        print('FAIL %s: %s' % (path, e))
