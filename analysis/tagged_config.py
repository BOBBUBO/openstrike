#!/usr/bin/env python3
"""Parser for the NetEase/Messiah *tagged binary* config format.

Grammar (reverse engineered from `TroyConfig/*.bin`, `LocalData/Config*` and
`essential_py3`):

    value := 's' u32le len  <bytes>        # string
           | 'i' u32le <int>              # 32-bit integer
           | '(' u32le n  <value> * n     # tuple / small map of n elements
           | '{' <value> * ...  '}'       # dict (elements until '}')

The top-level object of `essential_py3` is a dict whose keys are file names
(either a logical path such as `UIScript/auto_og_patch_scene_new0_ui.plist`
or an encrypted GUID path such as `ce/ce58e50afadf546376d4b76ea5b98899`)
and whose values are 2-element maps `{'s' <md5-hex>, 'i' <size>}`.
"""
import struct
import sys


class ParseError(Exception):
    pass


def parse_value(buf, pos):
    tag = buf[pos:pos + 1]
    pos += 1
    if tag == b"s":
        (n,) = struct.unpack_from("<I", buf, pos)
        pos += 4
        s = buf[pos:pos + n]
        if len(s) != n:
            raise ParseError("truncated string at %d" % pos)
        return s.decode("utf-8", "replace"), pos + n
    if tag == b"i":
        (v,) = struct.unpack_from("<I", buf, pos)
        return v, pos + 4
    if tag == b"(":
        (n,) = struct.unpack_from("<I", buf, pos)
        pos += 4
        items = []
        for _ in range(n):
            v, pos = parse_value(buf, pos)
            items.append(v)
        return items, pos
    if tag == b"{":
        out = []
        while pos < len(buf) and buf[pos:pos + 1] != b"}":
            v, pos = parse_value(buf, pos)
            out.append(v)
        if pos >= len(buf):
            raise ParseError("unterminated dict")
        return out, pos + 1
    raise ParseError("unknown tag %r at offset %d" % (tag, pos - 1))


TRAILER_RE = None


def find_trailer(buf):
    """Locate the file trailer `\x0c<32 hex>!|{` used by package files."""
    import re
    m = re.search(rb"0c[0-9a-f]{32}!\|\{", buf)
    return m.start() if m else len(buf)


def parse_top(buf):
    assert buf[0:1] == b"{", "top level must start with '{'"
    limit = find_trailer(buf)
    pos = 1
    out = []
    while pos < limit and buf[pos:pos + 1] != b"}":
        v, pos = parse_value(buf, pos)
        out.append(v)
    return out, pos


def main():
    path = sys.argv[1]
    buf = open(path, "rb").read()
    items, end = parse_top(buf)
    print("parsed %d top-level items, body consumed %d / %d bytes" % (len(items), end, len(buf)))
    print("trailer:", buf[end:end + 40])
    print()
    for it in items[:12]:
        print("  ", it)
    print("   ...")
    for it in items[-5:]:
        print("  ", it)


if __name__ == "__main__":
    main()
