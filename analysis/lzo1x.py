#!/usr/bin/env python3
"""Pure-python LZO1X decompressor (minilzo compatible, LZO1X-1).

Used to test whether NetEase's LocalData/Config* blobs are LZO-compressed
(the engine ships LzoDataDecompressor, which keys off the "ZZZZ" magic).
"""
from typing import Optional


def lzo1x_decompress(src: bytes, max_out: int = 1 << 26) -> bytes:
    out = bytearray()
    i = 0
    n = len(src)

    def copy_literals(k: int) -> None:
        nonlocal i
        if i + k > n:
            raise ValueError("literal overrun")
        out.extend(src[i:i + k])
        i += k

    if n == 0:
        return b""
    t = src[i]
    i += 1
    if t > 17:
        copy_literals(t - 17)
        t = src[i]
        i += 1
        if t < 16:
            raise ValueError("bad first match")

    while True:
        # match length / offset handling for t in 0..15
        if t >= 16:
            # t == 16: long literal length
            if t == 16:
                off = 1 + (src[i] >> 2) + (src[i + 1] << 6)
                i += 2
                copy_literals(off)
                t = src[i]
                i += 1
                if t < 16:
                    mlen = 3
                    mpos = len(out) - 1 - ((t >> 2) & 7) - (src[i] << 3)
                    i += 1
                    if mpos < 0:
                        raise ValueError("bad match pos")
                    for _ in range(mlen):
                        out.append(out[mpos])
                    t = src[i]
                    i += 1
                    continue
                # t >= 16 again -> 17.. (handled below)
            # t >= 18: match length
            mlen = (t & 7) + 1
            mpos = len(out) - 1 - ((t >> 3) & 31) - (src[i] << 5)
            i += 1
            if mpos < 0:
                raise ValueError("bad match pos")
            for _ in range(mlen):
                out.append(out[mpos])
            t = src[i]
            i += 1
            if t < 16:
                mlen = 3
                mpos = len(out) - 1 - ((t >> 2) & 7) - (src[i] << 3)
                i += 1
                if mpos < 0:
                    raise ValueError("bad match pos")
                for _ in range(mlen):
                    out.append(out[mpos])
                t = src[i]
                i += 1
            continue

        raise ValueError("unexpected token %d" % t)


def decompress_lzo1x(src: bytes, max_out: int = 1 << 26) -> bytes:
    """Full LZO1X-1 decompressor (the compact state machine above is only a
    partial helper; this is the canonical implementation)."""
    out = bytearray()
    ip = 0
    n = len(src)

    def need(k: int) -> None:
        if ip + k > n:
            raise ValueError("input overrun")

    t = src[ip]
    ip += 1
    if t > 17:
        need(t - 17)
        out += src[ip:ip + t - 17]
        ip += t - 17
        t = src[ip]
        ip += 1
        if t < 16:
            raise ValueError("bad first token %d" % t)

    while True:
        if t >= 16:
            if t == 16:
                need(2)
                off = 1 + (src[ip] >> 2) + (src[ip + 1] << 6)
                ip += 2
                need(off)
                out += src[ip:ip + off]
                ip += off
                t = src[ip]
                ip += 1
                if t < 16:
                    # M2 match: length 3, distance 1..1024
                    need(1)
                    dist = 1 + ((t >> 2) & 7) + (src[ip] << 3)
                    ip += 1
                    if dist > len(out):
                        raise ValueError("bad m2 distance")
                    for _ in range(3):
                        out.append(out[-dist])
                    t = src[ip]
                    ip += 1
                    if t < 16:
                        # M3 match
                        need(1)
                        dist = 1 + ((t >> 2) & 7) + (src[ip] << 3)
                        ip += 1
                        if dist > len(out):
                            raise ValueError("bad m3 distance")
                        for _ in range(3):
                            out.append(out[-dist])
                        t = src[ip]
                        ip += 1
                        if t < 16:
                            raise ValueError("loop")
                    continue
                # fall through to long match handling with t >= 18
            # long match
            mlen = (t & 7) + 1
            if t >= 18:
                need(1)
                dist = 1 + ((t >> 3) & 31) + (src[ip] << 5)
                ip += 1
                if t >= 64:
                    # M4: length encoded in extra bytes
                    while True:
                        need(1)
                        b = src[ip]
                        ip += 1
                        mlen += b
                        if b != 255:
                            break
                    if t >= 255:
                        need(1)
                        dist += 1 + (src[ip] << 8)
                        ip += 1
            if t >= 32:
                need(1)
                dist += 1 + (src[ip] << 8)
                ip += 1
            if dist > len(out):
                raise ValueError("bad match distance %d" % dist)
            for _ in range(mlen):
                out.append(out[-dist])
            t = src[ip]
            ip += 1
            continue

        # t < 16 : literal run
        if t == 0:
            need(1)
            while src[ip] == 0:
                t += 255
                ip += 1
                need(1)
            t += 15 + src[ip]
            ip += 1
        need(t + 3)
        out += src[ip:ip + t + 3]
        ip += t + 3
        t = src[ip]
        ip += 1
        if t < 16:
            need(1)
            dist = 1 + ((t >> 2) & 7) + (src[ip] << 3)
            ip += 1
            if dist > len(out):
                raise ValueError("bad m2 distance")
            for _ in range(3):
                out.append(out[-dist])
            t = src[ip]
            ip += 1
            if t < 16:
                need(1)
                dist = 1 + ((t >> 2) & 7) + (src[ip] << 3)
                ip += 1
                if dist > len(out):
                    raise ValueError("bad m3 distance")
                for _ in range(3):
                    out.append(out[-dist])
                t = src[ip]
                ip += 1
                if t < 16:
                    raise ValueError("loop")


def try_all_offsets(data: bytes, max_out: int = 1 << 24, limit: int = 256):
    """Try decompressing at every byte offset; return (offset, output) hits."""
    hits = []
    for off in range(min(limit, len(data))):
        try:
            out = decompress_lzo1x(data[off:], max_out)
            hits.append((off, out))
        except Exception:
            continue
    return hits


if __name__ == "__main__":
    import sys
    d = open(sys.argv[1], "rb").read()
    for off, out in try_all_offsets(d):
        print("LZO hit at offset %d -> %d bytes: %r" % (off, len(out), out[:64]))
