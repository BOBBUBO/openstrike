#!/usr/bin/env python3
"""Resolve C-string references (ADRP+ADD, ADRP+LDR) inside a function range,
using the RELOCATED libGame.so so that .data.rel.ro pointer tables are valid."""
import struct, sys

SO = sys.argv[1] if len(sys.argv) > 1 else 'analysis/libGame.relocated.so'
START = int(sys.argv[2], 0)
STOP = int(sys.argv[3], 0)
d = open(SO, 'rb').read()


def adrp_target(pc, w):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def cstr(addr, maxn=120):
    if addr <= 0 or addr + 8 > len(d):
        return None
    # only accept pointers into file-backed read-only/data regions
    if not (0x588b00 <= addr <= 0x71570e8):
        return None
    out = bytearray()
    for i in range(maxn):
        c = d[addr + i]
        if c == 0:
            break
        if c < 9 or (13 < c < 32) or c > 126:
            return None
        out.append(c)
    if not out:
        return None
    return out.decode('ascii')


pc = START
reg = {}
seen = {}
while pc + 4 <= STOP:
    w = struct.unpack_from('<I', d, pc)[0]
    if (w & 0x9F000000) == 0x90000000:
        reg[w & 31] = adrp_target(pc, w)
        pc += 4
        continue
    op = w & 0xFFC00000
    # LDR (unsigned imm64, scaled)
    if op == 0xF9400000:
        rn = (w >> 5) & 31
        rt = w & 31
        off = ((w >> 10) & 0xfff) * 8
        base = reg.get(rn)
        if base is not None:
            slot = base + off
            val = struct.unpack_from('<Q', d, slot)[0] if slot + 8 <= len(d) else 0
            s = cstr(val)
            if s:
                seen.setdefault((s, val), []).append(pc)
        reg.pop(rt, None)
        pc += 4
        continue
    # ADD immediate (64-bit)
    if (w & 0x7F800000) == 0x11000000:
        rn = (w >> 5) & 31
        rd = w & 31
        base = reg.get(rn)
        imm = (w >> 10) & 0xfff
        if (w >> 22) & 1:
            imm <<= 12
        if base is not None:
            s = cstr(base + imm)
            if s:
                seen.setdefault((s, base + imm), []).append(pc)
        reg.pop(rd, None)
        pc += 4
        continue
    if (w & 0x1F000000) == 0x0B000000 or op in (0xD2800000, 0xAA000000, 0xD3400000, 0xB9000000, 0x92800000):
        reg.pop(w & 31, None)
    pc += 4

for (s, addr), pcs in sorted(seen.items(), key=lambda kv: kv[1][0]):
    print('%-40r @0x%x  <- %s' % (s, addr, ' '.join('0x%x' % p for p in pcs[:4])))
print('total', len(seen))
