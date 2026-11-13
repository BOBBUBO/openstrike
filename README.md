# openstrike

Reverse-engineering of **Blood Strike** (`com.netease.newspike`) — the NetEase/Messiah
mobile title — focused on how the client talks to NetEase servers.

This repository contains **only the analysis tooling and the written findings**.
No game files are committed: no APK splits, no `*.mpk` archives, no extracted
maps/textures/patches, and no captured app data. Everything under `analysis/`
is either a *script* or a *small text artifact* produced by those scripts.

> **📄 The canonical report is [`analysis/FINDINGS.md`](analysis/FINDINGS.md).**
> Read that first — it contains every result, every correction and every
> remaining lead, with offsets and byte-level evidence.

---

## What was investigated

| Area | Status |
|---|---|
| Wire protocol (protobuf schemas, RPCs, handshake) | ✅ **Solved** |
| MPK container formats (`Resources*.mpk`, `Patch*.mpk`, indexes) | ✅ **Solved** |
| `.MESSIAH` asset container | ✅ **Solved** |
| Complete Android package file table (41,376 names → byte ranges) | ✅ **Solved** |
| MurmurHash3 x86_32 identification for `Resources.mpkinfo` | ✅ **Solved** |
| UniSDK **domain** server list (32 domains, real IPs) | ✅ **Solved / fetched live** |
| `regular_encode_*` environment SDK (Base64 → RC4 → LZMA) | ✅ **Solved** — it is *content moderation*, not the server list |
| `MImporter` encrypted-Python loader | 🟡 **Partial** (internals mapped, salt not yet recovered) |
| `LocalData/Config*` decryption | 🔴 **Open** |
| **Game** gate/server list (`server_list_host`, `cli_gateway`) | 🔴 **Open** — lives inside the encrypted `Config` |
| Transport choice (WebSocket vs KCP) | 🟡 **Partial** — both compiled in, decided at runtime |

---

## Repo layout

```
analysis/
  FINDINGS.md              ← ★ the canonical reverse-engineering report
  protos/                  ← recovered .proto schemas (client_gate, common,
                             gate_game, server_common) — package mobile.server
  serverlist/              ← the recovered SDK domain server list (JSON)
  *.py                     ← the tooling (see below)
  *.disasm                 ← objdump excerpts of the interesting code
  *.txt / *.json / *.jsonl ← string dumps, symbol dumps, small manifests
```

Everything else in the working tree is **git-ignored**:

```
stock-files/     captured app data + downloaded 2 GB of patches
decompiled/      apktool + jadx output
analysis/apk-split-base/, analysis/extracted-*/, analysis/essential/,
analysis/messiah-records/            raw extracted game bytes
analysis/*.bin, analysis/resources.json, analysis/*-records.jsonl,
analysis/package-file-table.jsonl    large generated indexes
```

They can all be regenerated with the committed scripts (see *Reproducing*).

---

## Tooling

All scripts are plain Python 3 with **no third-party dependencies**
(compression and crypto are reached through `ctypes` against the system
`liblz4` / `libzstd` / `libcrypto`).

### Containers & archives

| Script | Purpose |
|---|---|
| `lz4_block.py` | pure-Python LZ4 **block** decoder; returns bytes consumed |
| `mpk_extract.py` | global-offset-aware MPK extractor (`.MESSIAH`, LZ4 pages, raw, textures) + JSONL manifest |
| `parse_mpkinfo.py` | `Patch.mpkinfo` parser (multi-layout, GUID + named records) |
| `parse_resources_mpkinfo.py` | `Resources.mpkinfo` parser + MD5-trailer verification |
| `parse_resources1.py` | `Resources1.mpk` record-layer walker |
| `package_records.py` | `Resources1.mpk` record parser + LZ4 block-length walker |
| `package_index.py` | joins `Resources.mpkinfo` with the pack manifest |
| `build_file_table.py` | builds the complete name → byte-range → MD5 table |
| `scan_mpk_blocks.py`, `scan_package_blocks.py`, `scan_package_chunks.py`, `scan_zzz4_chunks.py` | LZ4 chunk scanners (`liblz4` via ctypes) |
| `scan_patch_records.py`, `scan_plain_patch_records.py` | brute-force record scanners for the patch archives |
| `sample_guid_payloads.py`, `probe_multichunk.py` | payload fingerprinting |
| `find_messiah_magic.py`, `dump_messiah_records.py`, `parse_messiah_container.py` | `.MESSIAH` container tools |

### Native / ARM64 analysis

| Script | Purpose |
|---|---|
| `find_arm64_xrefs.py` | ADRP+ADD / ADRP+LDR cross-reference finder |
| `find_bl_sites.py` | ARM64 direct `BL` call-site finder |
| `scan_globals_access.py` | walker over the Cython global pages (`.bss`) |
| `scan_relocs.py`, `dump_sections.py` | ELF section / relocation surveys |
| `ptr_index.py` | in-image pointer-table scanner (works around the packed `.rela.dyn`) |
| `cython_string_slots.py`, `cython_slots2.py` | recover Cython interned-string global slots |
| `find_cython_refs.py`, `find_frozen_modules.py`, `find_python_modules.py` | Cython / frozen / extension-module hunts |
| `find_slot_stores.py` | absolute-slot store scanner (superseded) |
| `extract_protos.py` | pulls the embedded `FileDescriptorProto`s out of `libGame.so` |

### Crypto

| Script | Purpose |
|---|---|
| `murmur3.py` | MurmurHash3 x86_32 — identifies `Resources.mpkinfo.digest0` |
| `lzo1x.py` | pure-Python LZO1X decoder (used to rule LZO out for `Config`) |
| `tagged_config.py` | parser for the engine's tagged binary config grammar (`s i ( { v p M`) |
| `config_xor_key.py` | autocorrelation / histogram analysis of `Config` |
| `try_config_rc4.py`, `try_config_keys.py`, `try_config_aes_modes.py`, `try_config_embedded_keys.py` | cipher campaigns against `Config` (all failed — see FINDINGS §4) |
| `crack_env_rc4.py` | RC4 + LZMA-header oracle cracker for the environment SDK |
| `decode_env_config.py` | working Base64 → RC4 → LZMA decoder for `regular_encode_*` |
| `solve_mimporter_salt.py`, `solve_mimporter_salt2.py` | data-driven salt solvers for `MImporter.filename_encrypt` |

### Misc

`search_mpk_blocks.py` (grep decompressed chunks for Python markers),
`scan_zlib_streams.py` (zlib/deflate finder), `find_messiah_magic.py`.

---

## Reproducing

The tooling expects this layout (all git-ignored):

```
stock-files/
  com.netease.newspike/files/LocalData/Patch/     Patch*.mpk, Patch.mpkinfo, …
  com.netease.newspike.1/files/…                   environment SDK artefacts
decompiled/
  native/lib/arm64-v8a/libGame.so                  the engine
  apk/split_base_mpk/apk/assets/…                 Resources.mpk / Resources1.mpk
  jadx/…                                           decompiled Java
```

Typical invocations (from the repo root):

```bash
# protobuf schemas out of the engine
python3 analysis/extract_protos.py

# complete package file table (name → offset → md5)
python3 analysis/parse_resources_mpkinfo.py
python3 analysis/build_file_table.py

# extract assets out of the patch archives by global offset
python3 analysis/mpk_extract.py --all

# scan the engine for Cython interned-string slots
python3 analysis/cython_slots2.py

# recover the SDK domain server list (network required)
curl -s https://dep410.update.easebar.com/g83naxx1ena.list
```

### External requirements

* `python3` ≥ 3.10 (standard library only)
* `binutils` (`objdump`, `readelf`, `nm`) for the native tooling
* optional: `liblz4.so.1`, `libzstd.so.1`, `libcrypto.so.3` (reached via `ctypes`)
* optional: `jadx` / `apktool` for the Java + resource layers
* optional: `curl` for the live network probes

---

## Legal / scope

This is a **read-only reverse-engineering study** of a shipped client, kept for
research, interoperability and archive purposes. It contains **no game
assets, no keys and no proprietary source** — only analysis notes and the
tools used to produce them. The scripts only read the files they are pointed
at; none of them modifies the game, talks to a game server, or bypasses any
protection. Respect the terms of service of the game and of NetEase, and
respect the copyright of the assets and of any third-party code you analyse.
The private-server feasibility discussion in `FINDINGS.md` is informational
only and explicitly limited to infrastructure you own.
