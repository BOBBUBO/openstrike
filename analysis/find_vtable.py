#!/usr/bin/env python3
"""Locate a C++ class in the relocated libGame.so via its RTTI typeinfo name.

Given the mangled typeinfo name (e.g. "N5async5logic25async_kcp_connection_implE")
it finds:
  * the typeinfo name string in .rodata
  * the __class_type_info object that points at it (absolute 8-byte pointer)
  * the vtable that points at that typeinfo (vtable[-1])
  * every virtual function pointer in that vtable

NOTE: section *virtual addresses* are NOT equal to their file offsets
(.data.rel.ro: vaddr 0x5d157c0, file offset 0x5d117c0) — every access goes
through `v2o()`.

Usage:
  python3 analysis/find_vtable.py N5async5logic25async_kcp_connection_implE
  python3 analysis/find_vtable.py --grep kcp_connection
"""
import re
import struct
import sys

SO = 'analysis/libGame.relocated.so'


class Elf(object):
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        d = self.d
        e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
        e_shentsize = struct.unpack_from('<H', d, 0x3A)[0]
        e_shnum = struct.unpack_from('<H', d, 0x3C)[0]
        e_shstrndx = struct.unpack_from('<H', d, 0x3E)[0]
        self.secs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            n, t, f, a, off, sz, l, inf, al, es = struct.unpack_from(
                '<IIQQQQIIQQ', d, o)
            self.secs.append(dict(name_off=n, type=t, addr=a, off=off, size=sz))
        st = self.secs[e_shstrndx]
        base = st['off']
        for s in self.secs:
            e = d.index(b'\0', base + s['name_off'])
            s['name'] = d[base + s['name_off']:e].decode()
        self.by_name = {s['name']: s for s in self.secs}

    def v2o(self, vaddr):
        """virtual address -> file offset"""
        for s in self.secs:
            if s['type'] == 8:
                continue
            if s['addr'] <= vaddr < s['addr'] + s['size']:
                return s['off'] + (vaddr - s['addr'])
        return None

    def q(self, vaddr):
        o = self.v2o(vaddr)
        if o is None:
            return None
        return struct.unpack_from('<Q', self.d, o)[0]

    def cstr(self, vaddr, maxlen=200):
        o = self.v2o(vaddr)
        if o is None:
            return None
        e = self.d.find(b'\0', o, o + maxlen)
        if e < 0:
            return None
        return self.d[o:e].decode('latin1')

    def scan8(self, target, secs=('.data.rel.ro', '.data', '.got', '.got.plt',
                                  '.rodata')):
        pat = struct.pack('<Q', target)
        out = []
        for nm in secs:
            s = self.by_name.get(nm)
            if not s or not s['size']:
                continue
            blob = self.d[s['off']:s['off'] + s['size']]
            i = 0
            while True:
                k = blob.find(pat, i)
                if k < 0:
                    break
                out.append((s['addr'] + k, nm))
                i = k + 1
        return out

    def find_names(self, want):
        out = []
        for s in self.secs:
            if s['type'] == 8 or not s['size']:
                continue
            blob = self.d[s['off']:s['off'] + s['size']]
            i = 0
            while True:
                k = blob.find(want, i)
                if k < 0:
                    break
                out.append(s['addr'] + k)
                i = k + 1
        return out


def main():
    e = Elf(SO)
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    if args and args[0] == '--grep':
        pat = re.compile(sys.argv[2])
        seen = set()
        for s in e.secs:
            if s['type'] == 8 or not s['size']:
                continue
            blob = e.d[s['off']:s['off'] + s['size']]
            for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{4,140}E', blob):
                txt = m.group().decode()
                if pat.search(txt) and txt not in seen:
                    seen.add(txt)
                    print('0x%x  %s' % (s['addr'] + m.start(), txt))
        return
    for want in args:
        wb = want.encode()
        hits = e.find_names(wb)
        print('== %s : %d name hits' % (want, len(hits)))
        for na in hits:
            for loc, sec in e.scan8(na):
                ti = loc - 8
                vts = e.scan8(ti)
                for v in vts:
                    print('   typeinfo 0x%x  vtable@0x%x (%s)'
                          % (ti, v[0] + 8, v[1]))
                    for k in range(0, 40):
                        fn = e.q(v[0] + 8 + 8 * k)
                        if fn is None or not (0x1dc0420 <= fn < 0x5d008b4):
                            break
                        print('      [%2d] 0x%x' % (k, fn))


if __name__ == '__main__':
    main()
