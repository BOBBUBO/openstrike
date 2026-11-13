import struct, collections, sys

p = 'decompiled/native/lib/arm64-v8a/libGame.so'
b = open(p, 'rb').read()
e_shoff = struct.unpack_from('<Q', b, 0x28)[0]
e_shentsize = struct.unpack_from('<H', b, 0x3a)[0]
e_shnum = struct.unpack_from('<H', b, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', b, 0x3e)[0]


def sh(i):
    o = e_shoff + i * e_shentsize
    v = struct.unpack_from('<IIQQQQIIQQ', b, o)
    return dict(name=v[0], typ=v[1], addr=v[3], off=v[4], size=v[5])


strtab = sh(e_shstrndx)


def nm(x):
    s = b[strtab['off'] + x:]
    return s[:s.index(b'\0')].decode()


secs = {nm(sh(i)['name']): sh(i) for i in range(e_shnum)}
r = secs['.rela.dyn']
out = open('analysis/rela-summary.txt', 'w')
out.write('rela.dyn size %d entries %d\n' % (r['size'], r['size'] // 24))
types = collections.Counter()
samples = []
target_lo = 0xa74000
target_hi = 0xa78000
hits = []
for i in range(r['size'] // 24):
    o = r['off'] + i * 24
    roff, rinfo, add = struct.unpack_from('<QQq', b, o)
    t = rinfo & 0xffffffff
    types[t] += 1
    if t == 1027:
        if len(samples) < 15:
            samples.append((hex(roff), hex(add)))
        if target_lo <= add <= target_hi:
            hits.append((roff, add))
out.write('types %r\n' % dict(types))
out.write('samples %r\n' % (samples,))
out.write('hits in python-string-table range: %d\n' % len(hits))
for roff, add in hits[:200]:
    s = b[add:add + 60]
    s = s[:s.index(b'\0')] if b'\0' in s else s
    out.write('  %s -> %s %r\n' % (hex(roff), hex(add), s))
out.close()
print('done')
