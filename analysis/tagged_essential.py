#!/usr/bin/env python3
"""
Parser for the "flat dict" tagged-binary format used by `essential_py3`
(different tag meanings from analysis/tagged_config2.py).

Grammar (derived by structural analysis of analysis/essential/essential_py3.bin):

    file    := '{' value* '}'
    value   := 's' u32le len  bytes[len]        # string
              | 'H' u32le n    (value value)*n  # hash / dict
              | '(' u32le n    value*n          # list / tuple
              | 'i' u32le v                     # int
              | 'p' u32le len  bytes[len]       # blob
              | 'v' u32le n    value*n
              | 'M' u32le n    value*n
              | '{' value* '}'
"""
import struct
import sys


class ParseError(Exception):
    pass


class P:
    def __init__(self, b):
        self.b = b
        self.p = 0

    def u8(self):
        v = self.b[self.p]
        self.p += 1
        return v

    def u16(self):
        v = struct.unpack_from('<H', self.b, self.p)[0]
        self.p += 2
        return v

    def u32(self):
        v = struct.unpack_from('<I', self.b, self.p)[0]
        self.p += 4
        return v

    def raw(self, n):
        v = self.b[self.p:self.p + n]
        if len(v) != n:
            raise ParseError('short raw at %d' % self.p)
        self.p += n
        return v

    def value(self):
        t = self.b[self.p:self.p + 1]
        self.p += 1
        if t == b's':
            n = self.u32()
            return self.raw(n).decode('utf-8', 'replace')
        if t == b'H':
            n = self.u32()
            d = {}
            for _ in range(n):
                k = self.value()
                v = self.value()
                d[k] = v
            return d
        if t in (b'(', b'v', b'M'):
            n = self.u32()
            return [self.value() for _ in range(n)]
        if t == b'i':
            return self.u32()
        if t == b'p':
            n = self.u32()
            return self.raw(n)
        if t == b'{':
            out = []
            while self.p < len(self.b) and self.b[self.p:self.p + 1] != b'}':
                out.append(self.value())
            if self.p >= len(self.b):
                raise ParseError('unterminated dict at %d' % self.p)
            self.p += 1
            return out
        raise ParseError('unknown tag %r at %d' % (t, self.p - 1))


def parse(buf):
    p = P(buf)
    assert buf[0:1] == b'{'
    p.p = 1
    items = []
    while p.p < len(buf) and buf[p.p:p.p + 1] != b'}':
        items.append(p.value())
    end = p.p + 1 if p.p < len(buf) else p.p
    return items, end


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'analysis/essential/essential_py3.bin'
    buf = open(path, 'rb').read()
    items, end = parse(buf)
    print('file %s  len=%d  parsed_to=%d  top_level_items=%d' %
          (path, len(buf), end, len(items)))
    print('trailer:', buf[end:end + 40])
    for it in items:
        if isinstance(it, dict):
            for k, v in it.items():
                print('  %-60s %s' % (k, repr(v)[:120]))
        else:
            print('  *', repr(it)[:160])
