#!/usr/bin/env python3
"""Find stores/loads to absolute Cython string slots (ADRP page + STR/LDR imm)."""
import re, sys, struct

SLOTS = {
    0x73cd380: 'salt',
    0x73cd168: 'md5',
    0x73ccdb0: 'decrypt_string',
    0x73cce80: 'filename_encrypt',
    0x73cd0e8: 'key',
    0x73cd428: 'head',
    0x73cd430: 'headlen',
    0x73cd7e0: 'sdata',
    0x73cd450: 'zlib',
    0x73cd158: 'marshal',
    0x73cd130: 'loads',
    0x73cd0d8: 'md5_x',
    0x73cd170: 'messiahForceEncrypt',
    0x73cd180: 'messiah_full_name',
    0x73cd190: 'messiah_mod',
    0x73cd248: 'open_file_data',
    0x73cd298: 'patch_root',
    0x73cd2e8: 'plain_finder',
    0x73cd358: 'real_root',
}

def slots_for_page(page):
    out = {}
    for a, n in SLOTS.items():
        if (a >> 12) == page:
            out[a & 0xfff] = n
    return out

def main(path):
    d = open(path, 'rb').read()
    TEXT_START, TEXT_END = 0x1dc0420, 0x5d008b4
    # ADRP: 1 1 0 0 0 0 0 0 0 0 0 0 0 immlo(2) immhi(19) Rd(5)
    adrp = re.compile(rb'\x00\x00\x00\x90', re.M)
    # stride scan
    prev = None
    hits = []
    i = TEXT_START
    while i < TEXT_END - 4:
        w = struct.unpack_from('<I', d, i)[0]
        if (w & 0x9f000000) == 0x90000000:  # ADRP
            rd = w & 0x1f
            imm = ((w >> 5) & 0x7ffff) << 12
            if w & 0x80000000:
                imm |= 0xfff00000
            page = (i & ~0xfff) + imm
            m = slots_for_page(page)
            if m:
                # look at next 1-3 instructions for str/ldr with matching imm
                for k in range(1, 4):
                    if i + 4*k + 4 > TEXT_END:
                        break
                    w2 = struct.unpack_from('<I', d, i + 4*k)[0]
                    # STR (unsigned imm) 64-bit: 1111 1001 00 imm12 Rn Rt
                    if (w2 & 0xffc00000) == 0xf9000000:
                        imm12 = (w2 >> 10) & 0xfff
                        rn = (w2 >> 5) & 0x1f
                        rt = w2 & 0x1f
                        if rn == rd and imm12 in m:
                            hits.append((i, i+4*k, m[imm12], 'STR', rt))
                    # LDR (unsigned imm) 64-bit: 1111 1001 01 imm12 Rn Rt
                    if (w2 & 0xffc00000) == 0xf9400000:
                        imm12 = (w2 >> 10) & 0xfff
                        rn = (w2 >> 5) & 0x1f
                        rt = w2 & 0x1f
                        if rn == rd and imm12 in m:
                            hits.append((i, i+4*k, m[imm12], 'LDR', rt))
                    # STR 32-bit: 1111 1001 00 imm12 ...
                    if (w2 & 0xffe00000) == 0xb9000000:
                        imm12 = (w2 >> 10) & 0xfff
                        rn = (w2 >> 5) & 0x1f
                        if rn == rd and imm12 in m:
                            hits.append((i, i+4*k, m[imm12], 'STR32', w2 & 0x1f))
                    # ADD immediate: 1 0 0 1 0 1 0 0 shift imm12 Rn Rd
                    if (w2 & 0xff800000) == 0x91000000:
                        imm12 = (w2 >> 10) & 0xfff
                        sh = (w2 >> 22) & 1
                        if sh:
                            imm12 <<= 12
                        rn = (w2 >> 5) & 0x1f
                        rd2 = w2 & 0x1f
                        if rn == rd and imm12 in m:
                            hits.append((i, i+4*k, m[imm12], 'ADD->slot', rd2))
        i += 4
    for h in hits:
        print('adrp 0x%x  op 0x%x  %-20s %-10s reg=x%d' % (h[0], h[1], h[2], h[3], h[4]))
    print('total', len(hits))

main(sys.argv[1] if len(sys.argv) > 1 else 'decompiled/native/lib/arm64-v8a/libGame.so')
