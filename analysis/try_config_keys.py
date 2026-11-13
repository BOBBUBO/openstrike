#!/usr/bin/env python3
"""Try likely locally-derived keys against the encrypted Config blobs.

This is a diagnostic brute-force over keys already present in the APK/app data
and common one-way derivations of them.  It does not download anything.
"""
import base64
import ctypes
import ctypes.util
import hashlib
import itertools
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "stock-files/com.netease.newspike/files/LocalData"

lib = ctypes.CDLL(ctypes.util.find_library("crypto"))
lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
lib.EVP_aes_128_ecb.restype = ctypes.c_void_p
lib.EVP_aes_192_ecb.restype = ctypes.c_void_p
lib.EVP_aes_256_ecb.restype = ctypes.c_void_p
lib.EVP_aes_128_cfb128.restype = ctypes.c_void_p
lib.EVP_aes_192_cfb128.restype = ctypes.c_void_p
lib.EVP_aes_256_cfb128.restype = ctypes.c_void_p
lib.EVP_aes_128_ctr.restype = ctypes.c_void_p
lib.EVP_aes_192_ctr.restype = ctypes.c_void_p
lib.EVP_aes_256_ctr.restype = ctypes.c_void_p
lib.EVP_rc4.restype = ctypes.c_void_p
lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_char_p, ctypes.c_char_p]
lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                  ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_int)]


def decrypt(cipher, key, data, iv=b"\0" * 16):
    ctx = lib.EVP_CIPHER_CTX_new()
    try:
        if not lib.EVP_DecryptInit_ex(ctx, cipher, None, key, iv):
            return None
        out = ctypes.create_string_buffer(len(data) + 32)
        n = ctypes.c_int()
        if not lib.EVP_DecryptUpdate(ctx, out, ctypes.byref(n), data, len(data)):
            return None
        result = out.raw[:n.value]
        final = ctypes.c_int()
        if not lib.EVP_DecryptFinal_ex(ctx, ctypes.byref(out, n.value), ctypes.byref(final)):
            return None
        return result + out.raw[n.value:n.value + final.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def score(data):
    if not data:
        return -1.0
    printable = sum(x in (9, 10, 13) or 32 <= x < 127 for x in data)
    zeros = data.count(0)
    # Reward JSON/ASCII and penalize large zero runs (common false positive).
    return printable / len(data) + min(zeros / len(data), 0.05) * 0.1


def candidates():
    literals = [
        b"g83naxx1ena", b"g83naxx1ena_1", b"g83naxx1ena_1_b221cacf",
        b"g83naxx1me", b"g83naxx2hmt", b"g83naxx2vn",
        b"0Qlwxya7S2WBxKvApJJIyw==", b"L2i/EfMjdV2XKT+tOcE1og==",
        b"g83naxx1ena\nd2ea3f5ca48b0caa6c6281f5f2251bf7\n1.003.650026",
        b"d2ea3f5ca48b0caa6c6281f5f2251bf7", b"1622853581",
        b"com.netease.newspike", b"g83naxx1ena_1_b221cacf1622853581",
    ]
    decoded = []
    for value in literals:
        decoded.append(value)
        try:
            decoded.append(base64.b64decode(value, validate=True))
        except Exception:
            pass
    decoded += [b"128", b"192", b"256"]

    out = {}
    for value in decoded:
        variants = {
            "raw": value,
            "md5": hashlib.md5(value).digest(),
            "sha1_16": hashlib.sha1(value).digest()[:16],
            "sha256_16": hashlib.sha256(value).digest()[:16],
            "sha256": hashlib.sha256(value).digest(),
        }
        for name, key in variants.items():
            if len(key) in (16, 24, 32):
                out[f"{value!r}/{name}"] = key
            if len(value) <= 32:
                out[f"{value!r}/zero-pad"] = value.ljust(32, b"\0")
    return out


def main():
    blobs = {name: (DATA / name).read_bytes() for name in ("Config", "Config_bak", "Config1")}
    keys = candidates()
    results = []
    for label, key in keys.items():
        for bits in (128, 192, 256):
            for mode in ("ecb", "cfb", "ctr"):
                cipher_name = f"EVP_aes_{bits}_{'cfb128' if mode == 'cfb' else mode}"
                cipher = getattr(lib, cipher_name)()
                for offset in (0, 4, 8, 16):
                    for iv_mode in ("zero", "header"):
                        if mode == "ecb" and iv_mode == "header":
                            continue
                        iv = b"\0" * 16
                        if iv_mode == "header":
                            iv = blobs["Config"][:16]
                        plain = decrypt(cipher, key, blobs["Config"][offset:], iv)
                        if plain is None:
                            continue
                        value = score(plain[:4096])
                        results.append((value, label, bits, mode, offset, iv_mode))
    results.sort(reverse=True)
    print(json.dumps({
        "candidate_count": len(keys),
        "best": [
            {"score": round(s, 5), "key": key, "bits": bits, "mode": mode,
             "offset": offset, "iv": iv}
            for s, key, bits, mode, offset, iv in results[:30]
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
