#!/usr/bin/env python3
"""Brute-force RC4/ARC4 keys against LocalData/Config* blobs.

Rationale: Config and Config_bak share an identical 148604-byte prefix but
differ afterwards.  That is the signature of a *stream* cipher with a static
key (plaintext prefix identical -> ciphertext prefix identical), not a block
cipher.  The engine ships `async.crypter.arc4_crypter` / PyCryptodome
`_ARC4`, so ARC4 is the prime candidate.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import itertools
import os
import re
import sys

LOCAL = os.path.join(os.path.dirname(__file__), "..", "stock-files",
                     "com.netease.newspike", "files", "LocalData")


def rc4(key: bytes, data: bytes, drop: int = 0) -> bytes:
    S = list(range(256))
    j = 0
    klen = len(key)
    if klen == 0:
        return data
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(len(data))
    for n, c in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        out[n] = c ^ k
    if drop:
        # recompute with N initial keystream bytes discarded
        S2 = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S2[i] + key[i % klen]) & 0xFF
            S2[i], S2[j] = S2[j], S2[i]
        i = j = 0
        for _ in range(drop):
            i = (i + 1) & 0xFF
            j = (j + S2[i]) & 0xFF
            S2[i], S2[j] = S2[j], S2[i]
        out2 = bytearray(len(data))
        for n in range(len(data)):
            i = (i + 1) & 0xFF
            j = (j + S2[i]) & 0xFF
            S2[i], S2[j] = S2[j], S2[i]
            k = S2[(S2[i] + S2[j]) & 0xFF]
            out2[n] = data[n] ^ k
        return bytes(out2)
    return bytes(out)


PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def score(data: bytes) -> float:
    if not data:
        return 0.0
    pr = sum(1 for b in data if b in PRINTABLE) / len(data)
    # reward ASCII words / JSON / XML markers
    txt = data.decode("latin1")
    bonus = 0.0
    for pat, w in ((r'https?://', 0.25), (r'\.com|\.net|\.cn', 0.1),
                   (r'[{}"\[\]]', 0.05), (r'[A-Za-z]{6,}', 0.05),
                   (r'(server|gate|login|host|port|ip)', 0.15)):
        m = len(re.findall(pat, txt, re.I))
        bonus += min(m, 40) * w
    return pr + bonus


def candidates() -> dict[str, bytes]:
    raw = [
        b"g83naxx1ena", b"g83naxx1ena_1", b"g83naxx1ena_1_b221cacf",
        b"b221cacf", b"g83naxx1me", b"g83naxx2hmt", b"g83naxx2vn",
        b"d2ea3f5ca48b0caa6c6281f5f2251bf7", b"1622853581",
        b"com.netease.newspike", b"newspike", b"bloodstrike",
        b"Blood Strike", b"Messiah", b"messiah", b"Netease", b"netease",
        b"0Qlwxya7S2WBxKvApJJIyw==", b"L2i/EfMjdV2XKT+tOcE1og==",
        b"8022f03148fd2c14f02ad37ad137d19f",
        b"g83naxx1ena_1_b221cacf1622853581",
        b"g83naxx1ena1622853581",
        b"169", b"650026", b"1.003.650026", b"2373",
        b"Config", b"Config1", b"LocalData", b"/LocalData/Config",
        b"bf5babb", b"\xbf\x5b\xab\xbb",
    ]
    for s in ("0Qlwxya7S2WBxKvApJJIyw==", "L2i/EfMjdV2XKT+tOcE1og=="):
        try:
            raw.append(base64.b64decode(s))
        except Exception:
            pass
    out: dict[str, bytes] = {}
    for k in raw:
        out[k.decode("latin1")] = k
        out[k.decode("latin1") + "|md5"] = hashlib.md5(k).digest()
        out[k.decode("latin1") + "|md5hex"] = hashlib.md5(k).hexdigest().encode()
        out[k.decode("latin1") + "|sha1_16"] = hashlib.sha1(k).digest()[:16]
        out[k.decode("latin1") + "|sha256_16"] = hashlib.sha256(k).digest()[:16]
        out[k.decode("latin1") + "|sha256"] = hashlib.sha256(k).digest()
        out[k.decode("latin1") + "|sha1"] = hashlib.sha1(k).digest()
    # hex strings found in the app data (md5-like) and shared prefs values
    extra = []
    prefs = os.path.join(os.path.dirname(LOCAL), "..", "..",
                         "com.netease.newspike.1", "shared_prefs")
    for fn in os.listdir(prefs) if os.path.isdir(prefs) else []:
        p = os.path.join(prefs, fn)
        try:
            txt = open(p, "r", errors="ignore").read()
        except Exception:
            continue
        for m in re.finditer(r"[0-9a-fA-F]{16,64}", txt):
            extra.append(m.group(0).encode())
        for m in re.finditer(r">([^<>]{4,64})<", txt):
            extra.append(m.group(1).encode())
    for e in extra:
        if 4 <= len(e) <= 64:
            out["prefs:" + e.decode("latin1")] = e
            try:
                out["prefshex:" + e.decode("latin1")] = binascii.unhexlify(e)
            except Exception:
                pass
    return out


def main() -> int:
    targets = []
    for name in ("Config", "Config1", "Config_bak"):
        p = os.path.join(LOCAL, name)
        if os.path.exists(p):
            targets.append((name, open(p, "rb").read()))
    cands = candidates()
    print(f"{len(cands)} candidate keys x {len(targets)} files")
    best = []
    for name, blob in targets:
        head = blob[:4096]
        for cname, key in cands.items():
            for drop in (0, 256, 768, 1024, 1536, 3072):
                d = rc4(key, head, drop)
                s = score(d)
                best.append((s, name, cname, drop, d[:64]))
        best.sort(key=lambda x: -x[0])
        print(f"--- {name}")
        for s, n, cn, dr, sample in best[:12]:
            print(f"  {s:8.3f} drop={dr:5d} {cn!r}  {sample[:48]!r}")
        best = []
    return 0


if __name__ == "__main__":
    sys.exit(main())
