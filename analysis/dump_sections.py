import struct
p = 'decompiled/native/lib/arm64-v8a/libGame.so'
b = open(p, 'rb').read()
e_shoff = struct.unpack_from('<Q', b, 0x28)[0]
e_shentsize = struct.unpack_from('<H', b, 0x3a)[0]
e_shnum = struct.unpack_from('<H', b, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', b, 0x3e)[0]
out = open('analysis/sections-dump.txt', 'w')
out.write('shoff=%x shentsize=%d shnum=%d shstrndx=%d\n' % (e_shoff, e_shentsize, e_shnum, e_shstrndx))


def sh(i):
    o = e_shoff + i * e_shentsize
    v = struct.unpack_from('<IIQQQQIIQQ', b, o)
    return v


strtab_off = sh(e_shstrndx)[4]
for i in range(e_shnum):
    v = sh(i)
    s = b[strtab_off + v[0]:]
    name = s[:s.index(b'\0')].decode()
    out.write('%2d %-24s type=%-10d addr=%012x off=%012x size=%012x es=%d\n'
              % (i, name, v[1], v[3], v[4], v[5], v[9]))
out.close()
print('ok')
