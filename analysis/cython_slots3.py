#!/usr/bin/env python3
"""Recover the Cython interned-string slot -> literal map for a Cython module.

Uses objdump's resolved disassembly: the module init pushes (slot_address,
cstring_address) pairs onto the stack frame, then interns them.  We track
register values through adrp/add/orr pairs and decode stp instructions that
write into the stack frame.
"""
import re
import subprocess
import sys

SO = 'decompiled/native/lib/arm64-v8a/libGame.so'
LO = int(sys.argv[1], 0)
HI = int(sys.argv[2], 0)
BLOB_LO = int(sys.argv[3], 0)
BLOB_HI = int(sys.argv[4], 0)

d = open(SO, 'rb').read()

out = subprocess.run(
    ['objdump', '-d', '--start-address=%#x' % LO, '--stop-address=%#x' % HI, SO],
    capture_output=True, text=True).stdout

ins_re = re.compile(r'^\s*([0-9a-f]+):\s+[0-9a-f ]+\t(\S+)\s*(.*)$')
reg = {}
pairs = {}
for line in out.splitlines():
    m = ins_re.match(line)
    if not m:
        continue
    pc = int(m.group(1), 16)
    op = m.group(2)
    rest = m.group(3)
    if op == 'adrp':
        mm = re.search(r'x(\d+),\s*([0-9a-f]+)', rest)
        if mm:
            reg[int(mm.group(1))] = int(mm.group(2), 16)
    elif op == 'add':
        mm = re.match(r'x(\d+),\s*x(\d+),\s*#(0x[0-9a-f]+|\d+)', rest)
        if mm:
            rd, rn, imm = int(mm.group(1)), int(mm.group(2)), int(mm.group(3), 0)
            if rn in reg:
                reg[rd] = reg[rn] + imm
            else:
                reg.pop(rd, None)
    elif op in ('stp',):
        mm = re.match(r'x(\d+),\s*x(\d+),\s*\[sp(?:,\s*#(0x[0-9a-f]+|\d+))?\]', rest)
        if mm:
            a = reg.get(int(mm.group(1)))
            b = reg.get(int(mm.group(2)))
            if a is not None and b is not None:
                for x, y in ((a, b), (b, a)):
                    if not (BLOB_LO <= x < BLOB_HI):
                        continue
                    e = d.find(b'\0', x)
                    if e < 0 or e - x > 200:
                        continue
                    try:
                        s = d[x:e].decode('utf-8')
                    except UnicodeDecodeError:
                        continue
                    if 0x73c0000 <= y <= 0x73e0000:
                        pairs.setdefault(y, set()).add(s)
    else:
        # crude clobber
        mm = re.match(r'x(\d+),', rest)
        if mm and op not in ('cmp', 'tst', 'cbz', 'cbnz', 'tbz', 'tbnz'):
            reg.pop(int(mm.group(1)), None)

res = sorted((slot, s) for slot, ss in pairs.items() for s in ss)
for slot, s in res:
    print('0x%08x %r' % (slot, s))
print('total', len(res))
