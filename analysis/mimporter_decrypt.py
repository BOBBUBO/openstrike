#!/usr/bin/env python3
"""
MImporter.decrypt_string -- EXACT reconstruction (verified against
analysis/decrypt_string.disasm, libGame.relocated.so @ 0x3a69dd8-0x3a6a9a8).

Disassembly evidence
--------------------
  0x3a69e54  mov x0,x24 ; bl 0x3739f78   -> PyObject_Length(data)      (n)
  0x3a69e68  sub x0,x0,#8                 -> n-8
  0x3a69ec0..0x3a69ee8                     -> (n-8) %% 37  (magic 0x3759f22983759f23,
                                               smulh/asr#3/msub, Python-sign fix-up)
  0x3a69f34  mov w9,#0x80 ; sub x0,x9,x8  -> 128-r
  0x3a69f78  mov x0,xzr ; bl 0x3782ba4    -> PyLong_FromLong(0)      (slice start)
  0x3a69f94  ldr x2,[0x64a4200]           -> Py_None                 (slice step!)
  0x3a69f98  bl 0x37a3afc                 -> PySlice_New(start,stop,step)
  0x3a69fc4  ldr x8,[x20,#8] ; blr x8     -> mp_subscript(data, slice)  => v = data[0:128-r]
  0x3a6a000  ldr x0,[0x64a7688]           -> bytearray type object
  0x3a6a00c  bl 0x3a6129c                 -> bytearray(v)
  0x3a6a0a0  ldrb w0,[x8,x20]             -> out[i]
  0x3a6a194  eor x0,x8,x24                -> out[i] ^ 0x9a (154)
  0x3a6a1b0  bl 0x373a724                 -> PyObject_SetItem(out, key, value)
  0x3a6a130  add x0,x8,#1                 -> key += 1  (stride 1, step is None)

=> the routine only touches the FIRST (128-r) bytes of its input: it is a
   HEADER decrypt, not a whole-file decrypt.
"""
import sys


def decrypt_string(data):
    """Exact port of MImporter.decrypt_string (bytes-like -> bytearray)."""
    n = len(data)
    r = (n - 8) % 37                 # Python-sign modulo (divisor > 0 => always >= 0)
    stop = 128 - r
    v = data[0:stop]
    out = bytearray(v)
    for i in range(len(out)):
        out[i] ^= 154
    return out


def head_len(n):
    """Number of bytes decrypt_string() actually rewrites for an input of length n."""
    return len(decrypt_string(bytes(n)))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--selftest':
        # sanity: r in [0,36] -> stop in [92,128]
        for n in (0, 1, 7, 8, 9, 36, 45, 100, 165175):
            print("n=%-8d r=%-3d stop=%-4d" % (n, (n - 8) % 37, head_len(n)))
    else:
        for path in sys.argv[1:]:
            raw = open(path, 'rb').read()
            dec = decrypt_string(raw)
            print("%s  n=%d  r=%d  decoded=%d bytes" %
                  (path, len(raw), (len(raw) - 8) % 37, len(dec)))
            print("   hex :", dec[:64].hex())
            print("   repr:", repr(bytes(dec[:64])))
