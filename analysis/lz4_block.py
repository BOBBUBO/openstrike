#!/usr/bin/env python3
"""Minimal LZ4 block-format decoder (safe, no dependencies)."""
from typing import Optional


def decompress(src: bytes, output_size: Optional[int] = None) -> bytes:
    out, _ = decompress_with_consumed(src, output_size)
    return out


def decompress_with_consumed(src: bytes, output_size: Optional[int] = None):
    """Decode an LZ4 block and return (output, number of source bytes consumed)."""
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        token = src[i]
        i += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                x = src[i]
                i += 1
                lit_len += x
                if x != 255:
                    break
        if i + lit_len > n:
            raise ValueError(f"literal overruns input at {i}, need {lit_len}")
        out += src[i:i + lit_len]
        i += lit_len
        if i == n:
            break
        if i + 2 > n:
            raise ValueError("truncated match offset")
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0 or offset > len(out):
            raise ValueError(f"invalid match offset {offset} at output {len(out)}")
        match_len = (token & 0x0F) + 4
        if (token & 0x0F) == 15:
            while True:
                x = src[i]
                i += 1
                match_len += x
                if x != 255:
                    break
        start = len(out) - offset
        # Overlapping copies are intentional in LZ4.
        for j in range(match_len):
            out.append(out[start + j])
        if output_size is not None and len(out) > output_size:
            raise ValueError(f"output exceeds expected size: {len(out)} > {output_size}")
    if output_size is not None and len(out) != output_size:
        raise ValueError(f"output size mismatch: {len(out)} != {output_size}")
    return bytes(out), i


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--size", type=int)
    a = ap.parse_args()
    with open(a.input, "rb") as f:
        data = f.read()
    result = decompress(data, a.size)
    with open(a.output, "wb") as f:
        f.write(result)
    print(f"wrote {len(result)} bytes")
