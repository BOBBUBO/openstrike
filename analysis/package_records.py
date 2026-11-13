#!/usr/bin/env python3
"""Rigorous walker for the Resources1.mpk (Android package) record structure.

Record layout (verified against the smallest consistent record @0x55a9dd2):

  +0x00  6 bytes  magic 02 02 02 01 01 2b
  +0x06  u8       version (1 / 6 / 7)
  +0x07  u8       flags (0 / 8)
  +0x08  u32 BE   count (always 1 in the samples)
  +0x0c  u16 BE   ? (1 or 2)
  +0x0e  u16 BE   ? (1 or 2)
  +0x10  16 bytes zero
  +0x20  u32 LE   payload_size  ==  next_record_offset - record_offset - 32
  +0x24  4 bytes  chunk tag 01 2b <ver> 00
  +0x28  u32 LE   36            (desc block length)
  +0x2c  12 bytes texture descriptor
  +0x38  4 bytes  payload magic (NNNN = encoded texture, ZZZ4 = LZ4 block)
  +0x3c  u32 LE   fmt (NNNN) | uncompressed_size (ZZZ4)
  +0x40  data[payload_size - 32]

For ZZZ4 the compressed data starts at +0x40 and its length is *not* stored;
it is recovered by walking the LZ4 block token stream.
"""
import struct
import sys

MAGIC = b"\x02\x02\x02\x01\x01\x2b"
TAG = b"\x01\x2b"


def lz4_block_compressed_size(src, start, limit):
    """Return the length of the LZ4 block at `start`, or None if invalid."""
    p = start
    end = limit
    while p < end:
        token = src[p]
        p += 1
        lit = token >> 4
        if lit == 15:
            while p < end:
                b = src[p]
                p += 1
                lit += b
                if b != 255:
                    break
            else:
                return None
        if p + lit > end:
            return None
        p += lit
        if p >= end:
            # last sequence: literals only
            return p - start
        if p + 2 > end:
            return None
        offset = src[p] | (src[p + 1] << 8)
        p += 2
        if offset == 0:
            return None
        mlen = token & 0x0F
        if mlen == 15:
            while p < end:
                b = src[p]
                p += 1
                mlen += b
                if b != 255:
                    break
            else:
                return None
        mlen += 4
        # a match must not reference before the start of the block
        if offset > (p - start):
            return None
    return p - start


def find_records(data):
    """Yield (offset, header_dict) for every record magic occurrence."""
    pos = 0
    while True:
        o = data.find(MAGIC, pos)
        if o < 0:
            return
        pos = o + 1
        yield o


def parse_header(data, o):
    ver = data[o + 6]
    flags = data[o + 7]
    count = int.from_bytes(data[o + 8:o + 12], "big")
    a = int.from_bytes(data[o + 12:o + 14], "big")
    b = int.from_bytes(data[o + 14:o + 16], "big")
    payload_size = struct.unpack_from("<I", data, o + 0x20)[0]
    tag = data[o + 0x24:o + 0x28]
    dlen = struct.unpack_from("<I", data, o + 0x28)[0]
    desc = data[o + 0x2C:o + 0x38]
    magic = data[o + 0x38:o + 0x3C]
    fmt = struct.unpack_from("<I", data, o + 0x3C)[0]
    return dict(offset=o, ver=ver, flags=flags, count=count, f12=a, f14=b,
                payload_size=payload_size, tag=tag, dlen=dlen, desc=desc,
                magic=magic, fmt=fmt)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else \
        "decompiled/apk/split_base_mpk/assets/Resources1.mpk"
    data = open(path, "rb").read()
    n = len(data)
    offs = [o for o in find_records(data)]
    print("magic occurrences: %d" % len(offs))

    kinds = {}
    sizes = []
    consistent = 0
    records = []
    for i, o in enumerate(offs):
        h = parse_header(data, o)
        nxt = offs[i + 1] if i + 1 < len(offs) else n
        h["next"] = nxt
        h["span"] = nxt - o
        h["data_len"] = h["payload_size"] - 32
        ok = (h["span"] == h["payload_size"] + 32)
        h["consistent"] = ok
        if ok:
            consistent += 1
        kinds[h["magic"]] = kinds.get(h["magic"], 0) + 1
        records.append(h)

    print("consistent records: %d / %d" % (consistent, len(records)))
    print("payload magic histogram: %s" % {k: v for k, v in sorted(kinds.items())})

    # dump a few ZZZ4 records and try to recover their compressed length
    zz = [h for h in records if h["magic"] == b"ZZZ4"]
    print("ZZZ4 records: %d" % len(zz))
    for h in zz[:10]:
        s = h["offset"] + 0x40
        clen = lz4_block_compressed_size(data, s, min(n, s + h["data_len"] + 4096))
        print("  @0x%x data_len=%d outsize=%d lz4_clen=%s  first=%s" % (
            h["offset"], h["data_len"], h["fmt"], clen,
            data[s:s + 16].hex()))

    nn = [h for h in records if h["magic"] == b"NNNN"]
    print("NNNN records: %d" % len(nn))
    for h in nn[:5]:
        d = h["desc"]
        print("  @0x%x desc=%s fmt=0x%08x data_len=%d" % (
            h["offset"], d.hex(), h["fmt"], h["data_len"]))

    other = [h for h in records if h["magic"] not in (b"NNNN", b"ZZZ4")]
    print("other payload magics: %d" % len(other))
    seen = {}
    for h in other:
        seen[h["magic"]] = seen.get(h["magic"], 0) + 1
    print("  top:", sorted(seen.items(), key=lambda kv: -kv[1])[:12])


if __name__ == "__main__":
    main()
