# Blood Strike (com.netease.newspike) — reverse-engineering findings

Working dir: `/root/projects/openstrike`
Targets: `decompiled/native/lib/arm64-v8a/libGame.so` (118,845,672 B),
`stock-files/com.netease.newspike/files/LocalData/**`,
`stock-files/com.netease.newspike.1/shared_prefs/**`.

> Status legend: **SOLVED** = format/algorithm fully recovered · **PARTIAL** = structure
> understood, one field outstanding · **OPEN** = not yet cracked.
>
> **Latest status (this session)**
> * **SOLVED — BIG WIN** — the **UniSDK domain server list is recovered live**:
>   `https://dep410.update.easebar.com/<gameid>.list` returns JSON with 32
>   domains, their **real A/AAAA IPs**, CDN aliases and fallback chains
>   (§1.2). Saved to `analysis/serverlist/g83naxx1ena.list.json`.
> * **SOLVED** — the complete Android package file table: 41,376 names → byte
>   ranges in `Resources1.mpk`, **0 ambiguities** (§2.3). `essential_py3`
>   extracted and MD5-verified.
> * **SOLVED** — `Resources.mpkinfo`'s `digest0` = **MurmurHash3 x86_32
>   (seed 0)** of the file name; `digest1` = the global file offset.
> * **SOLVED** — the `regular_encode` environment SDK decoder chain
>   (Base64 → RC4 → LZMA) — and the realisation that it is the
>   **content-moderation** regex list, *not* the server list (§4.5).
> * **PARTIAL** — `MImporter` internals: the **corrected** interned-string
>   slot map (244 entries, `analysis/cython-string-slots2.txt`), the
>   `gen_md5` XOR structure and the `filename_encrypt` closure constant
>   (`value ^ 0x7f`) are known; the salt *value* is not yet recovered (§3.5).
> * **PARTIAL** — `LocalData/Config*` structure mapped: an **88-byte header**,
>   a 148 KB unchanged body, changes localised to 148713–161554 and a
>   102-byte tail; the transform is **position-stable** (one 21-byte range
>   with constant XOR `0xc7`) ⇒ a static-key stream cipher over a *binary*
>   plaintext (§4.2).
> * **OPEN** — the encrypted Python modules, `LocalData/Config*` decryption,
>   and the **game** (gate) server list — which is *not* in the SDK `.list`
>   file but in the encrypted `Config` (§1.3).

---

## 1. Wire protocol (SOLVED)

The exact RPC schema is embedded in `libGame.so` as compiled `FileDescriptorProto`s
(`analysis/extract_protos.py` → `analysis/protos/*.proto`, package `mobile.server`).

```
client ──HTTPS/WS/KCP──▶ gate   (IGateService / IGateClient)
                              │  seed_request → session_key → connect_server
                              ▼
                            game   (IGameService)  AOI/entity replication, ping,
                                   reconnect, area migration
```

### Handshake (from `client_gate.proto`)

| step | rpc | payload |
|---|---|---|
| 1 | `seed_request` | client sends `EncryptString{encryptstr}` |
| 2 | — | gate replies `SessionSeed{seed, crypto}` |
| 3 | `session_key` | client sends `SessionKey{random_padding_header, session_key, seed, random_padding_tail, crypto}` |
| 4 | `connect_server` | `ConnectServerRequest{routes,type,clientid,entityid,reconnectkey,opt}` |
| 5 | — | gate replies `ConnectServerReply{routes,type,sindexes}` + `GateMsg{serverinfo,publicip,publicport,...}` |

`SessionKey` carries `random_padding_header`/`random_padding_tail` — a padding
obfuscation layer around the actual session key. `crypto` selects the algorithm.

### Other RPCs
`entity_message`, `reg_md5_index`, `update_pos_info`, `interest_entity`,
`traceroute`, `ctrl_message` (`CtrlMsg{typ,cmd}`).

### Native networking surface

The networking stack is a self-contained C++ library (`async::`) linked into
`libGame.so`. Mangled RTTI/type names give the exact class inventory
(`analysis/async-types.txt`, 280 entries):

```
async::net   connection, connection_manager, server, server_manager,
             tcp_server, tcp_listen_connection, tcp_connect_connection,
             tcp_ssl_listen_connection, tcp_ssl_connect_connection,
             telnet_server, telnet_connection,
             websocket_server, websocket_listen_connection,
             kcp_listen_connection, kcp_strand_pool::service_user,
             udp_pinger, write_buf
async::logic async_service<IGateClient, IGateService_Stub, mb_gate_client>,
             service_proxy, service_proxy_manager, service_manager,
             module_manager, timer_manager, io_manager,
             async_kcp_connection_impl, async_websocket_connection_impl,
             async_connection_impl, async_http_client_impl,
             async_bhttp_client_impl, async_bhttps_client_impl,
             area_manager_impl, area_impl, area_space_data,
             rpc_arg_{str,int,long,float,bool,tuple,list,dict,bytes,any,
                      customtype,entityid}
async::rpc  service, rpc_service, rpc_stream
```

**Transport (now determined structurally, see §1.1).**

* Boost.Asio + Boost.Beast, nghttp2 (HTTP/2), libcurl, OpenSSL statically linked.
* `asiocore.set_login_key(key, ispub)`, `asiocore.set_fec_switch_enable`,
  `asiocore.set_fec_switch_disable(rtt,num)` → KCP FEC.
* `async_kcp_connection`, `async_websocket_connection` → **both** transports exist;
  `enable_kcp_dupack`, `set_kcp_mh_handshake` are KCP tunables.
* `async.crypter.arc4_crypter` / `Crypto.Cipher._ARC4` → ARC4 available in the
  Python layer (PyCryptodome-style names) — likely the payload cipher.
* `send_connect_server`, `send_position_to_server` are Python-visible.

### 1.1 Transport: WebSocket (ws:// and wss://) and KCP are both compiled in

Two independent, fully instantiated client stacks exist:

| class | transport | evidence |
|---|---|---|
| `async::logic::async_websocket_connection_impl` | **WebSocket over TCP** | `boost::beast::websocket::stream<boost::beast::basic_stream<boost::asio::ip::tcp, executor, unlimited_rate_policy>, true>` instantiated for `async_websocket_connection_impl::handle_connect` / `handle_connected_read` (12 resolver-iterator overloads = IPv4/IPv6 × endpoint forms) |
| ” (TLS variant) | **WebSocket over TLS** | `boost::beast::websocket::stream<boost::asio::ssl::stream<boost::asio::basic_stream_socket<tcp>>, true>` instantiated for `websocket_listen_connection::start_work` (server side) |
| `async::logic::async_kcp_connection_impl` | **KCP over UDP** | `bind_socket_to_network(async::net::DSocketIndex, int, int)`, `on_socket_status_changed(DSocketIndex,int)`, `on_reconnected(DSocketIndex)`, `cleanup_impl2(DSocketIndex,string)`, `async::net::kcp_strand_pool::service_user` ⇒ dual-socket (v4+v6) UDP transport with reconnect handling |

* There is **no `ws://`/`wss://` literal** anywhere in `libGame.so` ⇒ the
  URL scheme is assembled at runtime (in the encrypted Python layer).
* The *server* side (`websocket_listen_connection`) is compiled in both plain
  and TLS flavours, so the engine is symmetric: the game can host a local
  WebSocket server (used by the in-app telnet/debug server) and connect out.
* `mb_gate_client` implements two RPCs natively: `ping(...)` and
  `traceroute(...)` (mangled names
  `N5async5logic14mb_gate_client4pingE…`, `…10tracerouteE…`).
* The **gate session** is created by
  `async::logic::async_service<mobile::server::IGateClient, IGateService_Stub, mb_gate_client>`,
  whose `on_connected()` / `clear_handler()` / `on_guard_destroy_ex(shared_ptr<async::net::connection>)`
  hooks are the native side of the Python-driven session.
* ⇒ The *runtime* choice between KCP and WebSocket is made by the **encrypted
  Python module** (or by a flag it reads out of the encrypted `Config`),
  **not** by the native engine. Evidence that KCP is the primary path for the
  live game: the whole KCP feature set is game-specific
  (`set_kcp_vgate`, `set_kcp_vginfo((ip,port,reserve1,reserve2,reserve3))`,
  `get_kcp_newstyle_handshake`, `set_kcp_mh_handshake`, `get_kcp_sync_magic`,
  `get_kcp_dual_socket_switch`, `enable_kcp_dupack`, FEC switch), whereas the
  WebSocket stack looks like a generic async framework that is also used for
  the embedded telnet/debug server.
* `GateMsg` (gate_game.proto) carries `vginfo`, `publicip`, `publicport`,
  `publicipv6`, `cross_connect`, `hostnum` ⇒ the gate hands the client the
  *real* game-server coordinates, possibly via a KCP "visual gate" relay
  (`asiocore.set_kcp_vgate(bool)`, `kcp use visual gate`).

### Server list
`com.netease.download.reporter.KeyConst` declares `KEY_SERVER_LIST_HOST`
("server_list_host") and `KEY_CLI_GATEWAY` ("cli_gateway"), but **nothing in the
Java code reads them** (verified by grepping every dex *and* every smali file;
only the declaration exists in `classes8.dex`). ⇒ the values are injected by
the native layer and are stored in the encrypted `LocalData/Config*` blobs.

**Correction (this session):** there are *two different* "server lists":

| list | source | contents | status |
|---|---|---|---|
| **SDK domain list** | `https://dep410.update.netease.com` → actually `dep410.update.easebar.com/<gameid>.list` | 32 UniSDK/telemetry/CDN domains + IPs | **RECOVERED** (§1.2) |
| **game gate list** | unknown host, named by the native layer as `server_list_host` / `cli_gateway` | the actual game servers | **OPEN** — inside the encrypted `Config` (§1.3) |

### 1.2 The UniSDK domain server list — **RECOVERED (live)**

Found in `com.netease.ntunisdk.evonet.core.Consts`:

```java
public static final String FALLBACK_URL_MAINLAND = "https://mgb.update.netease.com/";
public static final String FALLBACK_URL_OVERSEA  = "https://dep410.update.easebar.com/";
```

`com.netease.ntunisdk.evonet.fallback.FallbackImpl.getFallbackList(gameId)`
builds the URL:

```
https://mgb.update.netease.com/<gameId>.list        (mainland)
https://dep410.update.easebar.com/<gameId>.list      (oversea)
```

and parses the JSON with `FallbackImpl.parseFallbackItem()`:

| JSON key | meaning |
|---|---|
| `ip_addresses` | array of IPs → `DomainInfo.addIpAddress(ip, "anycast")` (`IpInfo.IP_FROM_SERVER_LIST = "anycast"`) |
| `domain_addr` | CDN / ALB aliases → `addFallbackAccDomain()` |
| `fallback_domain` | ordered fallback domains → `addFallbackDomain()` |
| `url` + `response` | speed-test probe (`/g83naxx1ena/ping` → `pong`) |

**Blood Strike (`g83naxx1ena`, oversea build) — fetched 2026-11-12, HTTP 200, 6,804 B**
(`analysis/serverlist/g83naxx1ena.list.json`; the MENA build `g83naxx1me` is
also saved). 32 domains, e.g.:

```
mgbnaeast-g83naxx1ena.unisdk.easebar.com  166.117.125.43, 35.71.130.235
    domain_addr  dep410-alb-unisdk-prod-170378-79-1527695619.ap-northeast-1.elb.amazonaws.com
    fallback     mgbnaeast-g83naxx1ena.ourgamelink.com
                 → mgbnaeast-g83naxx1ena-aws.unisdk.easebar.com
                 → mgbnaeast-g83naxx1ena-aliyun.unisdk.easebar.com
mgbnaeast.matrix.easebar.com               34.54.225.235
mgbcbnaeast-aws.matrix.easebar.com         13.248.207.39, 3.33.163.238
mgbsdknaeast.matrix.easebar.com            34.54.225.235
sdk-os.mpsdk.easebar.com                   34.102.237.119, 34.120.144.63, 35.227.232.247,
                                           99.83.244.92, 13.248.219.70, 15.197.133.246, 15.197.94.95
whoami.nie.easebar.com / who.nie.easebar.com / whoami.saser.tw
                                           75.2.58.19, 35.71.137.44, 35.244.229.179
kids-protection.mpsdk.easebar.com          34.102.237.119, …
```

The MGB service itself is live and answers
`GET https://mgbnaeast-g83naxx1ena.unisdk.easebar.com/g83naxx1ena/ping`
→ `pong` (Go-style router: `{"error_msg":"404 Route Not Found"}`).
Only `/<gameid>/ping` was found among ~25 guessed route names.

`mgb.update.netease.com` (mainland) returns **404** for the oversea game ids
while `dep410.update.easebar.com` returns **200** ⇒ this APK is the
oversea/global build.

### 1.3 Where the *game* gate list really comes from

* `com.netease.ntunisdk.base.ConstProp.ECHOES_SERVERLIST = "ECHOES_SERVERLIST"`
  is read by `SDKEchoes.createEhco2SAParams()` and uploaded as
  `server_list` — but it is **never set anywhere in Java** ⇒ the native
  engine sets it (through `SdkMgr.setPropStr`), i.e. it is read out of the
  encrypted `LocalData/Config`.
* The same is true of `KEY_SERVER_LIST_HOST` ("server_list_host") and
  `KEY_CLI_GATEWAY` ("cli_gateway") in
  `com.netease.download.reporter.KeyConst` — declared, never used in any
  dex/smali.
* The server list itself is **not JSON**: the recovered protobuf schema
  defines `ServerInfo{sid, ip, port, grp, extra, timestamp}` and
  `GateMsg{serverinfo, publicip, publicport, cross_connect, hostnum,
  publicipv6, vginfo}` ⇒ the client connects to one bootstrap host and the
  gate hands it the list of game servers over protobuf.
* ⇒ **The game gate host is inside the encrypted `LocalData/Config*`** (§4).

---

## 2. MPK container formats (SOLVED)

| file | format |
|---|---|
| `Resources.mpk` | magic `237MPTZSTD1` + zstd frame @+11 → 39,814,069 B JSON manifest (36,662 `dlcid_*` keys) |
| `Resources1.mpk` | `02 02 02 01 01 2b …` header; entries wrapped, chunk magic `NNNN` = already-encoded texture (ASTC/ETC), 24-byte descriptor at +0x20 |
| `Patch.mpk … Patch7.mpk` | `02 02 02 01 01 2b …` header; payload chunks `ZZZ4` = LZ4 block |
| `Patch6.mpk` | different container: `BKHD` → `DIDX` → `DATA` (RIFF/WAVE payloads) |
| `Engine.mpk` | TrueType/OpenType font blob |
| `Patch.mpk` | UTF-8 XML header (`<Root><Font>…`) then binary container with `MPT` markers |

### LZ4 chunk framing (verified, patch side)

Re-verified byte-exactly against a real record
(`15/15c923fc-f9d8-4830-9ee8-117b193e7c19.4`, stored 106,772 B):

```
+0x00  02 02 02 01 01 2b 01 00 0c 00 03 01 d8 06 e8 03   record header
+0x10  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
+0x20  f4 a0 01 00 00 01 2b 01 00 ec a0 01 00 d8 06 e8 03
+0x30  00 00 b0 0d f0 ae 06 00
+0x38  5a 5a 5a 34            <- "ZZZ4"  (engine compares 0x345a5a5a)
+0x3c  f0 ae 06 00            <- u32 output_size = 438000
+0x40  ...                    <- LZ4 block stream (consumes the rest of the record)
```

⇒ **chunk accounting:** a patch record contains exactly **one** chunk; the LZ4
stream always consumes the remainder of the stored record
(`trailing_bytes == 0`, verified on every sampled record).
The earlier "3–6 chunks per file" statistics were **false positives**: `ZZZ4`
and `NNNN` byte sequences occur *inside* the compressed payload itself.
`analysis/mpk_extract.py` now records `chunks`, `compressed_consumed` and
`trailing_bytes` per entry.

`ZZZZ` is also a **false positive** (byte-reversed spelling of the magic).

Tools: `analysis/lz4_block.py`, `analysis/mpk_extract.py`,
`analysis/scan_mpk_blocks.py`, `analysis/scan_package_blocks.py`,
`analysis/probe_multichunk.py`.

### Index files
* `Resources.mpkinfo` — `u32 version(3)`, `u32 count(45489)`, 45,489 × 20-byte
  records (`u8 kind`, `u8 path_suffix[3]`, `u32 digest0`, `u32 digest1`,
  `u32 logical_size`, `u32 flags`), then a 16-byte MD5 trailer that verifies
  over header+records. → `analysis/resources-mpkinfo.jsonl`
  * **Record semantics (decoded this round)**
    * `path_suffix` = the **last 3 characters of the file path** (e.g. `"py3"`
      for `essential_py3`, `"4.4"` for `…​.4` ASTC variants, `"ton"` for
      `*.skeleton`/`*.anim`/`*.motion`). The 3-char suffix histogram of the
      45,489 records matches the package file array **exactly** for every
      common suffix (`ton` 3039/3038, `nim` 1590/1590, `csb` 1403/1403,
      `ion` 1312/1304, `aph` 940/939, `bnk` 876/876, `0.4` 854/854 …) ⇒ the
      index and the file list describe the same file set.
    * `digest1` is a **Unix build timestamp**, not part of a hash: observed
      values `0x09d5022c` (2022‑05‑17), `0x09c42d27` (2022‑01‑11),
      `0x0a0a7600` (2023‑05‑24), `0x09ef8b4a` (2022‑09‑24),
      `0x0c16f08b` (2026‑07‑30) — all inside the asset-build window.
    * `digest0` is **not** the file MD5 (0/27,750 `common` entries match) and
      **not** a standard path hash (MurmurHash2‑64A seed 0 / seed
      `0xc70f6907`, libc++ `__hash_len_64`, FNV‑1a‑64 and CRC‑64/ECMA were
      all tested against 8 verified path↔digest pairs — 0 hits).
    * `flags`: `0` = ordinary file, `1` = directory (size 0), `2` = special
      (e.g. the Python modules).
    * **`essential_py3` is record #45 273** (`kind=13`, `suffix="py3"`,
      `logical_size=13329`, `flags=2`, `digest1=0x0c16f08b`). It is the **only**
      `py3` record in the whole index.
* `Patch.mpkinfo` — two record layouts:
  * GUID records: `u16 name_len` + `xx/uuid[-.N]` + `u64 stored_size` +
    `u16 md5_index` + 32-byte **ASCII-hex** MD5 + `u16 flags` + `u64 archive_offset`
    + `u32 logical_size` + 3 reserved
  * named assets: `u16 name_len` + path + `u32 stored_size` + `u32 md5_index` +
    `u16 md5_kind(=4)` + 32-byte **binary** MD5 + `u16 flags(0x100)` +
    `u64 archive_offset` + `u32 logical_size` + `u32 reserved`
  * `archive_offset` is **global** across `Patch.mpk … Patch7.mpk`; convert with
    the `ArchiveMap` in `analysis/mpk_extract.py`.
  * 65,422 records recovered (`analysis/patch-records.jsonl`), of which 894 are
    named assets (`analysis/patch-named-records.jsonl`).
* Index MD5 does **not** match the stored payload (it is the MD5 of the
  original, pre-encoding asset); `logical_size` is a constant ≈13,3xx for many
  records. Both are recorded in the extractor manifest as `md5_matches`.

### Patch CDN
`spike_patchlist_android_astc_512_py3.txt` preamble:
`202611101413 / 1346744ef807cb3997e591c950ff1933 / 146 / 400 /
 https://www.blood-strike.com/`, with
`@multisource_str_global@ = ((0.2,'g83-11.gph.easebar.com'),(0.6,'g83-12…'),(1.0,'g83-13…'))`.
`g83-11/12` resolve to Akamai (`a363.dscd.akamai.net`, `a1988.dscd.akamai.net`),
HTTP/2, `allow: POST, OPTIONS`; `g83-13` does not resolve from here.

---

## 2.1 `.MESSIAH` asset container (SOLVED)

The patch index contains 927 **unique** records whose stored payload starts with
the ASCII magic `.MESSIAH` (1,208 raw hits over the GUID-named records).
The magic does **not** occur in `libGame.so` ⇒ it is produced by an external
NetEase asset-pipeline tool, not by the engine.

```
offset 0x00  char magic[8]  = ".MESSIAH"
offset 0x08  u32 kind       = 1 | 2
offset 0x0c  body…         (body_len = record_len - 12)
```

| kind | count | body |
|---|---|---|
| 1 | 713 | 36-byte float blob, e.g. `e6 90 59 3c 55 92 89 3d 8a fc 0f 3e c5 16 e1 3d 4d 4c 26 3e 1f 10 00 00 c3 05 00 00 00 00 00 00` (material/transform constants) |
| 2 | 214 | name table: `u16 len + name`, then repeated `(u8 tag=1, u16 len + name)`, then a `u32` counter and a final `u16 len + text` property blob (`NormalEnable=1\ntBaseMap=…\ntNormalMap=…\n`) |

Example kind-2 record (`a4/a46e0188-af54-4518-a77a-5fafe8bf3a71`, 248 B):
```
"root_whole_models_sublevel_3_proxy_0_material"
"0941472e-f140-4c2d-8081-5232b15a61c8ProxyDefault"
```
Example kind-2 record (`1c/1cbef7fa-1dba-4e03-8a37-2df6c4d0b76e`):
```
"0941472e-f140-4c2d-8081-5232b15a61c8layer0"
```
⇒ these are **material/mesh hot-patch descriptors**, not Python.

Implementation: `analysis/parse_messiah_container.py` (standalone) and the
`.MESSIAH` branch inside `analysis/mpk_extract.py` (`decode_messiah`),
which now also reports `names` for kind-2 records.

## 2.2 `Resources1.mpk` package structure (SOLVED for the record layer)

`Resources1.mpk` (223,524,145 B) is a *bundle* container. The record framing
is now **fully decoded** (`analysis/package_records.py`):

```
record (0x24-byte header, then payload)
+0x00  6 B    magic 02 02 02 01 01 2b
+0x06  u8     version            (1,3,4,5,6,7,8,9)
+0x07  u8     flags              (0 or 8)
+0x08  u32BE  count / bitfield   (1, 769, 1281, 0x01000001, …)
+0x0c  u16BE  field A            (1, 2, 4, 512 … 32768)
+0x0e  u16BE  field B            (same domain)
+0x10  16 B   zero
+0x20  u32LE  payload_size  ==  next_record_offset - record_offset - 32
+0x24  4 B    chunk tag 01 2b <ver> 00
+0x28  u32LE  36                 (descriptor-block length)
+0x2c  12 B   descriptor         [w u16, h u16, ? u16, W u16, H u16, ? u16]
+0x38  4 B    payload magic       NNNN (raw ASTC page) | ZZZ4 (LZ4 block)
+0x3c  u32LE  fmt (NNNN) | uncompressed_size (ZZZ4)
+0x40  data[payload_size - 32]
```

* 2,651 records: **2,457 `NNNN`** (already-encoded ASTC pages, stored raw) and
  **194 `ZZZ4`** (LZ4-compressed 64 KiB virtual-texture pages). 2,566 of the
  2,651 records satisfy `payload_size == next_offset - offset - 32`
  (the first record and 84 others are false-positive magic hits inside binary
  data).
* The descriptor is a texture footprint: `08 00 08 00 00 00 10 00 10 00 00 00`
  (2,404×) = 8×8 block / 16×16 image; `00 02 00 02 00 00 00 04 00 00 01 00`
  (182×) = **512×512**, i.e. the `astc_512` variant named by the patch list.
* **The package also stores raw (uncompressed) game files.** The region
  ≈`0x82d2f8a…0xc172477` contains plaintext Cocos2d `.csb` content (Chinese
  strings, `AllowHeroMove+`, `AddRefTime\0AnimName\0Config\0…`).
* ⚠ **Correction of an earlier conclusion:** the `ZZZ4` at `0xa4a7c12` whose
  following `u32` is 13 329 (= the `essential_py3` size) is a **false
  positive** — it sits *inside* that raw CSB payload, and the bytes after it
  are plaintext (`+AddRefTime\0AnimName\0…`), not LZ4. The earlier claim that
  the `essential_py3` blob had been located is therefore **retracted**.
  Corollary: `ZZZ4` magic can occur by accident inside uncompressed assets, so
  every package-side "chunk" must be validated against the record framing.

### The package's three JSON manifests

| file offset | size | content |
|---|---|---|
| `0x0c172479` | 3,688,032 | `<32-hex md5>!|{ … }` → the **pack manifest** |
| `0x0d360f1b` | 35,881 | `{"file_list": {"Shader/es3/ShaderGraphParticle.cache": ["<md5>", 2145], …}}` — 437 **shader-cache** files |
| `0xc1791e9…0xc188789` | 62,880 | a 721-entry `name → [md5, size]` map (logical names + GUIDs) |
| `0xd369b44…0xd52ad31` | 1,839,597 | the **41,813-entry path↔GUID array** (the `packagefilelist`) — `essential_py3` is entry **29,713** |

**Pack manifest format (decoded):** `<32 hex chars>` `!|` `{` `<json>` `}`.
The JSON has 8 top-level keys:

```json
{
 "mpkexclude": ["prerequisite"],
 "file_sections": ["common", "android_common", "android_astc_512"],
 "common":            { "<logical path>": ["<md5>", <size>], … },   // 27,750
 "android_common":    { "<xx/uuid>":      ["<md5>", <size>], … },   //    721
 "android_astc_512":  { "<xx/uuid>":      ["<md5>", <size>], … },   // 12,905
 "android_common_32": {},
 "dlcid_pack_5004":   [ … ],
 "dlc_pack_5004":     [ … ]
}
```

* **The three sections partition the file set**: `common` = logical names
  shared by all platforms, `android_common` + `android_astc_512` = the
  platform-specific copies stored under **GUID** names (`52/52d6b827-…c8.4`).
  Their MD5 sets are **disjoint** (0 overlap).
* **`essential_py3` lives in the `android_astc_512` section**:
  `["bb060d6265e9052d549d4b5bdbf3a01d", 13329]` (entry #1,510).
* The manifest MD5 is the MD5 of the **original source asset**, never of the
  stored blob (0/27,750 `common` entries match any stored chunk MD5) ⇒
  MD5-based lookup inside the package is impossible; the name→blob mapping
  must be resolved **positionally**.
* The `<md5>!|` envelope is a *magic + content hash* wrapper. `MLauncher` also
  carries the literal **`4!|{`** and a module global `MAGIC`; the
  *essential/prerequisite filelist* blob that `MLauncher`/`MChecker` look for
  is **not present on disk** (the only `4!|{` hit inside `Patch2.mpk` is a
  false positive inside compressed data).
  **Correction (this session):** the single `4!|{` hit in `Resources1.mpk`
  (`0x0c172498`) is *also* a false positive — it is the last hex digit `4` of
  the pack-manifest MD5 (`…af1ddf2d4`) immediately followed by `!|{`.
  A full scan of `Resources1.mpk` finds **14** `!|{` occurrences and exactly
  **one** real envelope (the pack manifest at `0x0c172499`); the other 13 sit
  inside compressed/binary payloads. The only *genuine* `4!|{` literal in the
  whole APK is the Cython string-table entry at **`0xa76f9a`** in
  `MLauncher`'s string block (i.e. `MLauncher.MAGIC == "4!|{"`), so the
  essential/prerequisite filelist is **downloaded or generated at runtime**.

## 2.3 The complete Android package file table (SOLVED)

**`Resources.mpkinfo` record semantics — fully decoded:**

| field | meaning |
|---|---|
| `digest0` | **MurmurHash3 x86_32 (seed 0)** of the file name — **SOLVED** (`analysis/murmur3.py`; verified 3000/3000 on independent pairs; CRC32/ADLER32/FNV/djb2/sdbm/oat/murmur2/crc32c/md5-prefix all scored 0) |
| `digest1` | **global byte offset of the file body inside `Resources1.mpk`** (an earlier "Unix build timestamp" reading was wrong — those values merely looked like timestamps) |
| `suffix` | **last 3 characters** of the path (histogram matches the package file array exactly: `ton` 3039, `nim` 1590, `csb` 1403, `ion` 1312, `aph` 940, `bnk` 876, `0.4` 854, `4.4` 820 …) |
| `size` | byte length of the body |
| `flags` | `0` = ordinary, `1` = directory (size 0), `2` = special/raw-stored |

**Proof that `digest1` is an offset:** `essential_py3` is mpkinfo record
**#45,273** (`kind=13`, `suffix="py3"`, `size=13329`, `flags=2`,
`offset=0x0c16f08b`) — and the 13,329 bytes at `0x0c16f08b` hash to exactly
`bb060d6265e9052d549d4b5bdbf3a01d`, the MD5 published for `essential_py3` in
`spike_patchlist_android_astc_512_py3.txt`.

**`essential_py3` — EXTRACTED and MD5-verified**

```
offset 0x0c16f08b   length 13,329   md5 bb060d6265e9052d549d4b5bdbf3a01d
saved to analysis/essential/essential_py3.bin
```

It is **not** Python source but a *tagged binary dict* (parser
`analysis/tagged_config.py`; tags `'s'` u32LE-len string, `'i'` u32LE int,
`'('` u32LE count + n values, `'{'` dict until `'}'`): **306 top-level items**,
13,292 of 13,329 bytes consumed, trailer
`0c305315703f13299c18023e2af1ddf2d4!|{` = `0c` + *pack-manifest MD5* + `!|{`
(a reference to the manifest, type tag `0c`). It contains **153**
`name → [md5, size]` entries, mixing logical paths (`UIScript/…`, `Char/…`)
and GUID paths (`xx/uuid`) — **153/153 match the pack manifest exactly**.
⇒ The `0c<md5>!|{` trailer is a *manifest reference footer* used by
package files; `Collision.bin` (plaintext, `0x0c164140`, 31,859 B) has **no**
trailer, so the footer is specific to manifest-style files.

**The definitive name → byte-range table** — `analysis/build_file_table.py`
(resolution order: `md5(body)+size` → `murmur3(name)` bucket → `+size` filter →
ambiguity list):

```
mpkinfo_records        45,489
named_total/unique     41,376
  resolved by md5      17,878
  resolved by hash     22,777
  resolved by hash+size  721
directories             3,668
unresolved                445
ambiguity_histogram       {}      ← 0 ambiguous
```

Outputs: `analysis/package-file-table.jsonl` (45,489 rows: name, section,
`md5_original`, `md5_stored`, size, offset, container, flags, suffix,
`digest0`, method, candidates) and
`analysis/package-file-table-unresolved.jsonl` (445 rows).

* **31,452** of the named files use the **GUID namespace** (`xx/uuid`),
  9,924 keep logical names.
* 23,498 are “transformed” (stored MD5 ≠ manifest MD5): **21,344 GUID +
  2,154 logical**.
* ⚠ **Correction (this session):** `flags = 0` does **not** mean “encrypted”.
  A 3,000-sample prefix histogram of the `flags=0` bodies shows no common
  header at all, and the mean Shannon entropy of a 300-file sample is
  **7.069** with a *minimum of 0* (i.e. plaintext files are present in the
  same bucket). The MD5 mismatch simply means the manifest MD5 refers to the
  **original source asset** while the stored blob is the **packed** form
  (ASTC texture pages, LZ4 pages, …). ⇒ There is **no** second, hidden
  encrypted namespace inside the Android package.
* ⇒ **No Python logic modules ship inside the Android package.** All 2,144
  “python-ish” hits in the table are `UIScript/*.csb` / `UIScript/*.plist`.
  The encrypted logic must arrive from the patch/CDN channel or a separate
  package.

## 3. Python runtime — the game scripts are ENCRYPTED

* `.PyRuntime` section (vaddr `0x7136510`, file `0x712e510`, 0x27d70 B) contains
  **only CPython runtime internals** — no game modules.
* No `.py` / `.pyc` / `.pyo` inside any patch MPK LZ4 block
  (12,281 blocks scanned, 0 hits for `import `, `def `, `AccountManager`,
  `seed_request`, `ws://` …), none in `Resources1.mpk` (202 blocks),
  none in `packagefilelist` (41,813 paths), none in `Resources.mpk`'s manifest.
* The loader is a **Cython module compiled into libGame.so**:

```
src/Runtime/Plugins/Python/Source/MImporter_py3.cpp
module MImporter  (Cython)
  decrypt_string, filename_encrypt, gen_md5, new_module,
  setImporterPath, setLazyImportEnabled, stopImporter,
  finder.find_spec / find_spec_in_anywhere / find_spec_in_encrypt /
          find_spec_in_patch_encrypt / find_spec_in_pkg_encrypt,
  finder.get_relpath(_with_path), finder.get_encrypt_name_with_path,
  finder.create_module / exec_module / get_module / get_module_data,
  finder._create_module / _load_encrypted_module / _lazy_import_module,
  plain_finder.get_module, inspect_ismodule, normpath_nt/posix
```

Four Cython modules total: `MChecker.py` (0xa7476c), `MGameBuildin.py`
(0xa75438), `MImporter_py3.py` (0xa76206), `MLauncher.py` (0xa76f76).

Native (non-Cython) Python modules exposed to the game include
**`MAsyncore`**, **`_lz4block`**, `asiocore` (`gate_client`, `set_login_key`,
`set_fec_switch_*`, `del_all_timers`, `get_timer_info`), `AccountManager`
(`Login/Logout/Pay/SetPropStr/SetPropInt/GetPropInt/HasLogin/QueryRoom/…`),
`gclient.util`.

### MImporter internals (partially reversed)
* Interned-string global slot table base **`0x73ccba8`** (235 entries recovered —
  `analysis/cython-string-slots.txt`). Slot examples:
  `md5`→0x73cd168, `salt`→0x73cd380, `decrypt_string`→0x73ccdb0,
  `filename_encrypt`→0x73cce80, `marshal`→0x73cd158, `zlib`→0x73cd450,
  `loads`→0x73cd130, `hex`→0x73ccfe0, `hexdigest`→0x73ccfe8, `key`→0x73cd0e8,
  `head`→0x73cd428, `headlen`→0x73cd430, `encrypt_file_path`→0x73cd448,
  `encrypt_filename`→0x73cd458, `encrypt_pkg_path`→0x73cd468,
  `encrypt_pkgname`→0x73cd478, `md5_x`→0x73cd0d8, `_md5`→0x73cd138,
  `sdata`→0x73cd7e0.
* xref backbone (relocations are unusable — `.rela.dyn` is packed with an
  `APS2` blob): `analysis/find_arm64_xrefs.py` + `analysis/cython_string_slots.py`.
  A second, independent backbone is now available: `analysis/ptr_index.py`
  scans every file-backed data section for 8-byte in-image pointers
  (41,718 slots → 15,398 distinct targets, `analysis/ptr-index.json`).
* **Cython string constants are reached through a pointer table, not
  ADRP+ADD.** `adrp x1, 0x6c84000` + `ldr x1, [x1, #3232]` (site `0x39da52c`)
  loads the pointer at `0x6c84ca0`. Consequently raw 8-byte pointer searches
  and `ADR` scans for the *string address* return nothing — search for the
  **pointer-table slot** instead.
* The constant table around `0x6c84c80` holds length-prefixed (1-byte length)
  C strings used by the MImporter module-init function at `0x39da500`:

```
0x6c84c9c  "main"            (slot 0x6c84ca0)
0x6c84cb0  "Script/Python"   (slot 0x6c84cb8)
0x6c84cc8  "/Lib3"           (slot 0x6c84cd0)
```
  ⇒ the importer searches **`Script/Python`** and **`/Lib3`** relative roots;
  `main` is the entry module. The function at `0x39da500` fills the whole
  constants/slots table with a dense run of `str xN, [x14, #imm]`.
* Immediately after that table, `0x6c84e80…` holds the **engine→script callback
  names** (also 1-byte length prefixed): `FinishInit`, `FinishRegister`,
  `FinishLogin`, `&LoginDoneWithDetail`, `FinishLogout`, `PaymentClosed`,
  `ManagerClosed`, `WebViewCallback`, `ShareEnd`, `SnCreated`,
  `$FinishMobileVerify`, `OpenExitViewFail`, `JoystickEvent`, `ReviewResult`,
  `DownloadProgress`, `DownloadFinish`, `DownloadStart`, `DownloadError`,
  `DownloadDel`, `PharosProbe`, `PharosHarbor`, `PharosQos`,
  `$ExtendFuncCallback`, `CreateQRCodeCallback`, `ScanQRCodeCallback`,
  `QueryMyAccountCallback`, `EncodePNGCallback`, `DarenUpdated`,
  `ProtocolFin…`
* Hot spots:
  * `0x3a696ec` – `gen_md5`: looks up `hashlib.md5` via the slot `md5`
    (loaded at `0x3a697ac`), iterates the argument list, `eor x0, x8, x0` at
    `0x3a69610` mixes a 64-bit value with `[x19+16]`.
  * `0x3a6b1e4` – the `key`-using routine (selectors `0x1df9/0x1df1/0x1e14`).
  * `0x3a6d780` – `decrypt_string` + `zlib` consumer (loads two .bss slots
    `0x73cd8e8` / `0x73cd8f0`).
  * `0x3a5c4a4`, `0x3a5cb04`, `0x3a71d9c…0x3a71e70` – `filename_encrypt` users.
  * `eor` instructions in the cluster: `0x3a68d88` (`eor x8,x22,#0x7f`),
    `0x3a69610`, `0x3a6a194`.
* `MImporter` string table also contains `ENCRYPTED_MODULE_CACHE`, `FILL_CACHE`,
  `LOGICROOT`, `PATCHROOT`, `REALROOT`, `USE_CACHE`, `USE_LAZY_IMPORT`,
  `FileExistInPackage/Patch`, `GetRawDataInPackage/Patch`,
  `OpenFileDataInPackage/Patch`, `data not exists in pacakge` *(sic)*.

### 3.1 The patch-side key file (NEW — likely the MImporter key source)

`LocalData/Patch/` contains two *plaintext* key files that are not part of any
MPK:

```
Patch/0a/0a0ab8a4-df96-4d5-9a862-967c2adca6f   (58 B)
Patch/0d/0d0ab9a4-df96-4d5-9a862-967c2abca6f   (58 B)
   content (identical):
   71ad02b5-a3ec-4ec4-9c89-3b0979779444-1794371578-1794371578
```

and one *UIScript* stub:

```
Patch/UIScript/4051BDD0000f042.pyo   (36 B)
   content: 71ad02b5-a3ec-4ec4-9c89-3b0979779444
```

Interpretation:
* the file name is `<2-hex-dir><uuid>` — the **same** UUID naming scheme the
  patch index uses for GUID records (`xx/uuid`),
* the content is `<uuid>-<unix-ts>-<unix-ts>`; `1794371578` = 2026‑11‑11
  (matches the patch-list timestamp `202611101413` and the `update_data_time`
  `1794371582869` in `environment_preferences_config.xml`),
* the `.pyo` file holds only the 36-char UUID — i.e. the **plaintext key
  without the timestamp suffix**, and its name `4051BDD0000f042` is an
  obfuscated token rather than a UUID.

⇒ This is very likely the input to `MImporter.gen_md5` (which mixes `md5` +
`salt`) or to `filename_encrypt`: the importer derives the **encrypted module
filename** from this key, and the module blob itself is stored under that
derived name. Testing this seed directly as an XOR key against
`LocalData/Config*` (seed, uuid, and their md5/sha1/sha256 derivatives) gives
only random-looking output — so the cipher is not a plain repeating XOR.

### 3.2 `TroyConfig/*.bin` — the *plaintext* sibling of `Config`

`LocalData/Patch/TroyConfig/` holds two **readable** binary config files:

```
Collision.bin  31,859 B   header a9 5b e5 be b3 1d 39 e5 e5 ef 9d …
Graphics.bin   15,271 B   header b1 b4 ab 1b 39 bb 91 25 90 51 …
```

Their body is a NetEase **tagged binary config format**:
`u16 name_len + name + type_tag` where the tags observed are
`'s'` (string), `'v'` (vector), `'p'` (pointer/ref), `'M'` (map) — e.g.

```
0e 00 "CollisionFlags" 73 01000000
09 00 "flagitems"     76 4d 02000000 73 03000000
06 00 "group1"        70 04000000 …
```

`LocalData/Config` (165,175 B) has the same *shape* of header
(`bf 5b ab bb`, and `Config1` → `bf 5b b2 51`; note both `Config*` and
`TroyConfig/*` start with `?? 5b`) but its body is high-entropy ⇒
**`Config` is the same config format, encrypted**. This gives a *known-plaintext
handle*: once the key is recovered, the decrypted `Config` must parse as the
tagged format above, which is a strong validator (and lets us attack the
cipher with a crib).

### 3.3 Frozen-module table: not present in plaintext

`analysis/find_frozen_modules.py` scanned every writable section for a
16-byte `{name_ptr, code_ptr}` frozen-module table: only **13** candidate
module-name strings are referenced from data and **no table was found** ⇒ the
frozen module table is itself encrypted (or stored non-standard), consistent
with everything else in §3.

**Consequence:** the Python game logic (asyncore client, gate/game protocol
drivers) is *not* recoverable as plain source from the shipped APK; it must be
decrypted at runtime by `MImporter` (md5+salt naming, `zlib` after
decryption, `marshal`/`exec` to load).

### 3.4 The bootstrap chain: MLauncher → MChecker → MImporter (NEW)

The complete Cython string tables (`0xa74a60 … 0xa77a00`) were dumped this
round; they give the **exact job of each boot module** and therefore the order
in which the encrypted assets are consumed.

**`MLauncher.py`** — the *first* module to run. Its embedded docstring
(Chinese) says:

> 此模块负责检查更新引擎启动所需要的资源，如shader cache/resource.repository
> 和MChecker不同，此模块在引擎各模块Initialize之前调用
> (“this module checks the resources needed to start the updated engine, e.g.
> shader cache / resource.repository; unlike MChecker it is called **before**
> the engine's module Initialize.”)

API surface: `MAGIC`, **`4!|{`**, `Filelist`, `Filelist_name`, `Entry`, `Text`,
`prerequisite`, `prerequisite_py3`, `essential_data`, `essential_md5`,
`filelist`, `filelist_data`, `filelist_size`, `filemd5`, `filepath`,
`filesize`, `realmd5`, `md5cache`, `md5_cache_ok`, `sizecache`,
`size_cache_ok`, `patch_script_path`, `pkg_script_path`, `CreateFileInPatch`,
`DeleteFileInPatch`, `FinishPatch`, `PatchTick`, `OpenFileDataInPackage`,
`OpenFileDataInPatch`, `GetRawDataInPackage`, `GetRawDataInPatch`,
`FileExistInPackage`, `FileExistInPatch`, `Result`, `IS_PY3`,
`useReloadImporter`, `MReloadImporter`, `MPatch`, `PKGROOT`, `PATCHROOT`,
`gen_md5`, `setPath`, `OpenFileData`, `SetPatchTickFunc`, `check`, `keys`,
`aftercheck`, `md5`, `_md5`, `hexdigest`, `marshal`, `loads`, `chr`, `decode`.

Log strings reveal the algorithm:
`++++ [[ load essential file list ]]`, `++ load prerequisite file`,
`++++ use essential files in package`, `++ check file in prerequisite list`,
`^_^ prerequisite filelist is okay -> enter main`,
`no prerequisite filelist exists -> enter main`,
`-- prerequisite file exist in patch`, `-- [[prerequisite file size <= 36]]`,
`+-|| file md5 not right: `, `-_-|| file size not right: `,
`++++xx delete file in patch (md5): / (md5 cache): / (size): / (size cache): `.

**⇒ The “prerequisite/essential filelist” is a blob whose first bytes are the
4-byte magic `4!|{`; its payload is a JSON list of `{filepath, filesize,
filemd5}` entries that is compared against the package and the patch.**

**`MChecker.py`** — verifies the *package* against the *patch*.
API: `SimplePatchMpk` (`__init__`, `check_mpk_info`, `load_meta_info`,
`load_mpk_info`, `update_engine_mpk_info`, `update_mpk_data_size`,
`get_mpk_data_relative_path`, `open_db`, `try_load`, `cleanup`, `on_exception`),
an **LMDB** database (`meta_db`, `info_db`, `map_size`, `max_dbs`, `txn`,
`cursor`), `essential`, `essential_data`, `essential_md5`, `essential_py3`,
`essential_in_patch`, `filelist*`, `filemd5`, `realmd5`, `filepath`,
`filesize`, `use_mpk_hash_key`, `mpkkey`, `MReloadImporter`,
`struct`/`unpack` with format **`=QH32sBBQ`** (= `u64 stored_size`,
`u16 name_len`, 32-byte MD5, `u8 flags`, `u8 kind`, `u64 archive_offset`),
`gen_md5`, `OpenFileData`, `IsNewPackage`, `load_patch_mpk`,
`close_patch_mpk`, `pkgversion`, `shadercachelist_%s.txt`.

**`MGameBuildin.py`** — **not** crypto: it is a large pure-math helper
(`Vec2/Vec3/Matrix4x3/Size/Direction`, `distance*`, `lerp`, `normalize`,
`angle`, `inRange`, `GetDodgePosition`, `wayPoint`, …). Useful as a
*deobfuscation-free* reference for the game’s coordinate conventions.

**`MImporter.py`** — the encrypted-module loader. Full surface:
`LOGICROOT`, `PATCHROOT`, `REALROOT`, `PATH_LIST`, `ENCRYPTED_MODULE_CACHE`,
`FILL_CACHE`, `USE_CACHE`, `USE_LAZY_IMPORT`, `PathFinder`, `SpecInfo`,
`BuiltinImporter`, `FrozenImporter`, `filename_encrypt`,
`encrypt_file_path`, `encrypt_filename`, `encrypt_pkg_path`,
`encrypt_pkgname`, `decrypt_string`, `gen_md5`, `new_module`,
`finder.find_spec` / `find_spec_in_anywhere` / `find_spec_in_encrypt` /
`find_spec_in_patch_encrypt` / `find_spec_in_pkg_encrypt`,
`finder.get_encrypt_name_with_path`, `finder.get_module_data`,
`finder._load_encrypted_module`, `finder._lazy_import_module`,
`finder._import_module`, `plain_finder.*`, `lazyimporter`,
`open_file_data`, `open_file_data_in_package`, `open_file_data_in_patch`,
`GetRawDataInPackage`, `GetRawDataInPatch`, `FileExistInPackage`,
`FileExistInPatch`, `isEncrypt`, `messiahForceEncrypt`, `messiah_full_name`,
`messiah_mod`, `messiah_cdata`, `messiah_loaded`, `comp`, `comps`,
`new_comps`, and the crypto locals **`head`, `headlen`, `sdata`, `key`,
`salt`, `cdata`, `data`, `datalen`** plus `decompress`, `zlib`, `marshal`,
`loads`, `code`, `hex`, `hexdigest`, `md5`, `_md5`.

**⇒ Reconstructed load algorithm**

```
1. relpath = finder.get_relpath(fullname)
2. name    = filename_encrypt(relpath)         # md5(salt + relpath)-based
3. raw     = open_file_data_in_package(name)    # or ..._in_patch(name)
4. head, sdata = raw[:headlen], raw[headlen:]
5. key     = gen_md5(salt)                      # md5 slot + salt slot
6. cdata   = xor/rotate-decrypt(sdata, key)
7. code    = marshal.loads(zlib.decompress(cdata))
8. exec_module(code)                            # creates the module object
```

The decryption primitive itself is still inside the Cython-compiled
`decrypt_string` (consumer at `0x3a6d780–0x3a6d960`, which loads the `zlib`
slot `0x73cd450` at `0x3a6d904` and the `decrypt_string` slot `0x73ccdb0` at
`0x3a6d838`).

### 3.5 MImporter internals — hard numbers (NEW)

**Module-state layout.** Cython keeps every module-level name in a
*module-state struct*. The MImporter state struct is reached as `x8` inside
the module-init function; the **name → offset** mapping was recovered by
reading the init code that stores the literal address of each name next to the
address of its slot (`adrp x10, 0xa76000; add x10, x10, #imm; str x10,[sp,#N]`
followed by `add x10, x8, #slot; str x10,[sp,#N-8]`):

| name | module-state offset | name | module-state offset |
|---|---|---|---|
| `replace` | `0x7c8` | `head` | `0x7d8`* |
| `rfind` | `0x7d0` | `sdata` | `0x7e0` |
| **`salt`** | **`0x7d8`** | `self` | `0x7e8` |

(*the `salt` slot is the one confirmed by the init code below.)

**The `salt` object.** The module-init copies the salt into the global slot:

```
3a59420  adrp x8, 73cc000
3a59424  ldr  x0, [x8, #3648]     ; ← PyObject* at 0x73cce40   (the SALT)
3a59428  bl   3a60150              ;   incref / intern
3a5942c  adrp x8, 73cd000
3a59430  str  x0, [x8, #2008]     ; → module global 'salt' at 0x73cd7d8
```

`0x73cce40` lives in **`.bss`** (`.bss` = vaddr `0x715e280`, size `0xef1f30`,
so it is zero at load time) ⇒ the salt is built at runtime by the Cython
init, not a file-backed constant. `analysis/scan_globals_access.py` enumerates
every ADRP+`LDR`/`STR` touching the Cython global pages `0x73cb000–0x73ce000`
(9,460 accesses in `.text`) and is the tool to use for further work on it.

**`gen_md5` — the hash is an XOR with a 64-bit constant.**
Inside the Cython `gen_md5` body the digest is read as an integer and then
XOR-ed:

```
3a6960c  ldr  x8, [x19, #16]      ; 64-bit constant (the salt)
3a69610  eor  x0, x8, x0          ; result = digest_int ^ salt
3a69614  bl   3781870             ; PyLong_FromUnsignedLongLong
```

A second, *constant* XOR appears in the `filename_encrypt` closure builder:

```
3a68d60  mov  w22, w8             ; python int → C int
3a68d88  eor  x8, x22, #0x7f      ; ★  value ^ 0x7f   (captured in a closure cell)
3a68d94  str  x8, [x19, #16]
3a68db4  bl   3a60270              ; build the nested function object
```

⇒ `filename_encrypt` is a **nested lambda that captures a 64-bit constant**
`value ^ 0x7f`; that captured constant is the salt. The function object is
created with the C string at `0x6c8c5f8` and the helper functions at
`0x73cce88` / `0x73ccc78` / `0x73ccba8`.

**Solving for the salt from data is possible in principle.** If the mapping is
`guid = render(md5_int ^ salt)`, then for any known *(logical name → GUID)*
pair the salt is `md5_int ^ guid_int`, with 6 bits masked out by the forced
UUID-v4 version/variant nibbles. A first attempt
(`analysis/solve_mimporter_salt2.py`, 379,074 `dlcid_* → xx/uuid` pairs taken
from `spike_patchlist_android_astc_512_py3.txt`) produced **no** consistent
salt for any of the 7 name-forms × 4 digest-slices × 6 guid-renderings
tested ⇒ the *input string* that is hashed is **not** the raw `dlcid_*`
key (it is probably the full relative path, e.g. `Script/Python/<module>`,
or the name is salted before hashing).

**`MImporter` string table (complete).** `0xa76200–0xa76ec1`:
`MImporter_py3.py`, `ENCRYPTED_MODULE_CACHE`, `FILL_CACHE`, `USE_CACHE`,
`USE_LAZY_IMPORT`, `LOGICROOT`, `PATCHROOT`, `REALROOT`, `PATH_LIST`,
`PathFinder`, `SpecInfo`, `BuiltinImporter`, `FrozenImporter`,
`filename_encrypt.<locals>.<lambda>`, `encrypt_file_path`,
`encrypt_filename`, `encrypt_pkg_path`, `encrypt_pkgname`,
`finder.*`, `plain_finder.*`, `isEncrypt`, `messiahForceEncrypt`,
`messiah_full_name`, `messiah_mod`, `messiah_cdata`, `messiah_loaded`,
`data not exists in pacakge` *(sic)*, `cache_key`, `altsep`, `backslash`,
`builtin_module_names`, `asyncio.coroutines`.

**`MLauncher` string table** (`0xa76ec1–0xa77200`): `MAGIC`, **`4!|{`**,
`Filelist`, `prerequisite`, `prerequisite_py3`, `essential_data`,
`essential_md5`, `filelist*`, `filemd5`, `filepath`, `filesize`, `realmd5`,
`md5cache`, `md5_cache_ok`, `sizecache`, `size_cache_ok`,
`patch_script_path`, `pkg_script_path`, `CreateFileInPatch`,
`DeleteFileInPatch`, `FinishPatch`, `PatchTick`, `OpenFileDataInPackage`,
`OpenFileDataInPatch`, `GetRawDataInPackage`, `GetRawDataInPatch`,
`FileExistInPackage`, `FileExistInPatch`, `IS_PY3`, `useReloadImporter`,
`MReloadImporter`, `MPatch`, `PKGROOT`, `PATCHROOT`, `gen_md5`, `setPath`,
`OpenFileData`, `SetPatchTickFunc`, `check`, `keys`, `aftercheck`, `md5`,
`_md5`, `hexdigest`, `marshal`, `loads`, `chr`, `decode`; plus the log
strings `++++ [[ load essential file list ]]`, `++ load prerequisite file`,
`^_^ prerequisite filelist is okay -> enter main`,
`no prerequisite filelist exists -> enter main`,
`+-|| file md5 not right: `, `-_-|| file size not right: `.

**New class found:** `N7Messiah12PythonModuleE` with
`ZN7Messiah12PythonModuleC1Ev`, `…16_Construct_on_otEv`,
`…11StartModuleEv`, `…5StartEv` and three lambdas
(`…StartModuleEv…clEvEUlfE_…`, `…StartEv…`). This is the **native bootstrap
that starts the Python layer** — the right place to look for the
`Script/Python` + `/Lib3` search-path setup.

### 3.6 Corrected Cython interned-string slot map (NEW)

`analysis/cython_slots2.py` (new) fixes a bug in `analysis/cython_string_slots.py`:
the latter assumed the ADRP base register was always `x8` *and* added the
`BASE` page offset twice, which shifted every slot by `0xa8`. The new tool
tracks the ADRP page of **every** register and recognises
`ADD xd, xn, #imm` with `page(xn) == 0x73cc000` ⇒ slot = `0x73ccba8 + imm`.

Result: **244 interned-string slots** (`analysis/cython-string-slots2.txt`),
9 more than before:

```
0x73ccf50 'finder.get_relpath'      0x73ccf78 'full_name'
0x73ccf80 'gc'                      0x73ccf88 'gen_md5'
0x73cd268 'origin'                  0x73cd270 'p'
0x73cd278 'parent'                  0x73cd280 'parent_module'
0x73cd300 'plain_finder.find_module'
```

**IMPORTANT CORRECTION to §3.5:** the slots `0x73cd380 … 0x73cd3b8` are the
*interned name strings* for the module-level variables, **not** the variables
themselves:

```
interned NAME slot      module-state VALUE slot
'salt'      0x73cd380   0x73cd7d8
'sdata'     0x73cd388   0x73cd7e0
'self'      0x73cd390   0x73cd7e8
'sep'       0x73cd3a0   0x73cd7f0
'__set_name__' 0x73cd3b8   0x73cd7f8
'replace'   0x73cd370   0x73cd7c8
'rfind'     0x73cd378   0x73cd7d0
```

(`0x73cd000` = base of the MImporter module-state struct; the interned
string table lives at `0x73ccc08 … 0x73cd450` inside the same page.)

The earlier claim that “the salt object lives at `0x73cce40`” is **wrong**:
`0x73cce40` is the interned string **`enumerate`**. The code at `0x3a59424`
(`ldr x0,[x8,#0xe40]` → `0x73cce40`) copies the *string* `"enumerate"` into
the module-state slot `0x73cd7d8`; the real salt **value** is therefore
whatever `0x73cd740` (the only other module-state slot written in that
region, at `0x3a5f5a4`) holds — it is produced by a helper call at
`0x3a5f580` with 8 arguments.

Also note `decrypt_string` is called with **two** attribute assignments
before use:

```
0x3a6d830  SetAttr(decrypt_string@0x73ccdb0, name@0x73cd8e8, value@0x73cd8f0)
0x3a6d904  SetAttr(zlib@0x73cd450,          name@0x73cc8f8, value@0x73cd900)
```

(`0x73cd8e8/8f0/900` and `0x73cc8f8` are module-state slots, not interned
strings — their names still have to be recovered.)

The `filename_encrypt` function object (`0x73cce80`) is likewise given
attributes at `0x3a5c4a4` / `0x3a5cb04` / `0x3a71da8` / `0x3a7d55c`
(`SetAttr(filename_encrypt, module-state@0x73ccac0, module-state@0x73ccac8)`).

---

## 4. `LocalData/Config*` blobs (NOT YET DECRYPTED)

```
LocalData/Config       165,175 B   header bf 5b ab bb
LocalData/Config_write 165,175 B   byte-identical to Config
LocalData/Config_bak   165,073 B   header bf 5b ab bb
LocalData/Config1         749 B   header bf 5b b2 51
LocalData/Config1_write    749 B   byte-identical to Config1
```

Facts established:
* No zlib/gzip/lz4/zstd/xz/bzip2/zip signature anywhere.
* All 256 byte values present; high entropy.
* `Config` vs `Config_bak`: byte 0..87 equal, 88..108 **differ**, 109..148,603
  **equal** again, then further differences; 16,069 differing bytes in total over
  171 contiguous ranges ⇒ deterministic cipher with a **static key** and only
  localised plaintext changes.
* The change at 88..108 touches only 5 of the 16 bytes of the 16-byte block that
  starts at 96 ⇒ **not ECB**; the cipher is a byte-stream/CTR/CFB-style
  transform (or a mono-alphabetic table).
* Autocorrelation over shifts 1..2048 is flat (≈1/256 ⇒ no repeating-key XOR).
* Byte histogram is nearly flat (max 0.54 % vs 0.39 % expected, χ²=3004 for
  255 df) — consistent with RC4-style keystream bias over binary/compressed
  plaintext, *not* with a substitution of ASCII text.
* `Config1` ends with a **run of five identical bytes** (`b9 b9 b9 b9 b9` at
  0x2e5) — impossible for a positional stream cipher ⇒ either the tail is
  special (appended after encryption) or the cipher is block based.

### 4.2 `Config` ↔ `Config_bak` diff structure (NEW — narrows the cipher)

Full range-by-range diff (`Config` 165,175 B vs `Config_bak` 165,073 B):

```
common prefix                  : 0 … 87          (88 bytes, identical)
first difference               : 88 … 108        (21 bytes, CONSTANT XOR 0xc7)
identical again                : 109 … 148,712   (148,604 bytes!)
changed region                 : 148,713 … 161,553
identical again                : 161,554 … 165,072
Config has 102 extra bytes     : 165,073 … 165,174  (tail, not present in _bak)
```

171 differing ranges total, of which 60 have a single constant XOR value —
**but 59 of those are 1–3 bytes long**, where "constant XOR" is vacuous.
Only **one** long range (21 B) has a genuinely constant XOR (`0xc7`).

Interpretation:

* The cipher is **position-stable** (the same keystream byte at the same
  offset produced `Config_bak`), i.e. a stream/CTR/CFB-style transform with a
  static key — *not* ECB.
* The plaintext is **binary**, not text: inside the changed region most
  single-byte differences are **single-bit flips** (`xor ∈ {0x01,0x02,0x03,
  0x04,0x06,0x08,0x0c,0x10,0x18,0x1c,0x20,0x28,0x30,0x40,0x60,0x80,…}`),
  exactly what you get when a float/int field in a serialised config changes.
  ⇒ the plaintext is the same *tagged binary* format as `TroyConfig/*.bin`
  (`u16 name_len + name + type_tag + value`, tags `s i ( { v p M`).
* The 21-byte range at offset 88 with a constant XOR `0xc7` is the one place
  where the *plaintext* changed by a fixed byte-wise delta (probably a string
  field whose every character moved by `0xc7`, or a fixed-width identifier).
* `Config` ends with a tail that is *not* in `Config_bak`:
  `… ff 4d af 4a 74 12 75 fc c5 7e 94 7f 51 a3 fc 1f 29 47 76 c9 08 c6 44
  bc 7d b1 78 e9 5d 15 57 2d e5 ff 6c 2d f3 fb ff 01 f8 32 50 0f b9 b9 b8
  bf bc b8 bf be`
  and `Config1` with `… 0b 0e b9 b9 b9 b9 b9 be bd b8`. The shared `b9 b9 …`
  + `be/b8` ending suggests a **fixed trailer** (checksum / terminator).
* The four-byte headers differ only in the last two bytes:
  `Config` = `bf 5b ab bb`, `Config1` = `bf 5b b2 51`, `Config_bak` =
  `bf 5b ab bb`. `Config` and `Config_bak` share the header exactly ⇒ the
  header is *plaintext* (or a constant) and the 2-byte field at offset 2 is
  per-file data (size/version). `Config`/`Config1` also share the first two
  bytes `bf 5b`; `TroyConfig/Collision.bin` = `a9 5b e5 be` and
  `TroyConfig/Graphics.bin` = `b1 b4 ab 1b` (also a 4-byte header).
* ⇒ **next attack**: treat `Config[0:2]` as a magic, brute-force the 2-byte
  field at offset 2, and use the 88-byte header as a known-plaintext crib to
  test keystream candidates derived from `MImporter.gen_md5(salt)`.

### 4.3 `LuckyFile` — a 21-byte crib in the same family (NEW)

`LocalData/LuckyFile` was overlooked so far. It belongs to the same family:

```
file            len   head            tail (last 10 bytes)
Config        165175  bf 5b ab bb    50 0f b9 b9 b8 bf bc b8 bf be
Config_bak    165073  bf 5b ab bb    0c 74 b9 b9 b8 bf bc b9 bf bc
Config1          749  bf 5b b2 51    0b 0e b9 b9 b9 b9 b9 be bd b8
LuckyFile        21  bf 5b ac a7    c6 02 b9 b9 b9 b9 b9 b9 b8 ba
```

Observations:

* **All four share the 2-byte magic `bf 5b`**; the next two bytes differ per
  file (`ab bb` / `b2 51` / `ac a7`).
* **All four end with a run of `b9` bytes** (2×, 2×, 5×, 6×) followed by
  2–3 bytes in the `b8..bf` range. `Config` and `Config_bak` even share the
  5-byte sequence `b9 b9 b8 bf bc`.
* `Config` and `Config_bak` have an **identical 4-byte header** ⇒ the key is
  **global**, not derived from the file name (otherwise `Config_bak` would
  have a different header), while `Config1`/`LuckyFile` share only the
  2-byte magic ⇒ bytes 2..3 are per-file data.
* ⇒ the family is: `magic(2)` + per-file data + a **common trailer** whose
  first bytes are `b9 b9 …`. Because the `b9` run appears in *all* files at
  roughly the same distance from EOF, it is most likely a **fixed plaintext
  marker** (e.g. a “end of table” sentinel) that is *not* encrypted, or a
  fixed keystream artefact at those offsets.

**`LuckyFile` is the smallest sample (21 B) and is the best crib available:**
if the plaintext is the tagged-binary-dict format used by
`TroyConfig/*.bin` / `essential_py3` (`{` + u32 count + `u16 len`+name+
tag+value … + `}`), a 19-byte body can be brute-forced against the known
tag bytes (`s i ( { v p M`) once the keystream is known.

### 4.4 Structural facts about the `Config` cipher

* Tag-byte frequencies in `Config` are all ≈ 1.0× the uniform expectation
  (`'s'` 591, `'i'` 892, `'('` 574, `'{'` 635, `'v'` 533, `'p'` 561,
  `'M'` 750 vs 645 expected) ⇒ the file is **fully encrypted**, not a
  plaintext tagged config.
* High-bit distribution is exactly 50.99 % over the whole file and
  50.39 % / 51.42 % in the changed / tail regions ⇒ uniform ciphertext.
* The 2-byte magic `bf 5b` is therefore the only *plaintext* header we have.
* CRC16/CRC32/adler32 checksums of every suffix of the files were tested
  against every 2-/4-byte window: **no match** ⇒ the trailer is not a
  checksum over the ciphertext (it would be over the plaintext).
* Filenames `Config_bak`, `Config_write`, `Config1_write`, `LocalData/Config`
  are **absent from every native .so and every dex** ⇒ the path is assembled at
  runtime (the standalone `"Config"` string at `0x6c2b2e` is a PhysX Python
  module name — `Config`, `Coordinate`, `Nodes`, `Beams`, `Hydros`, `Wheels`,
  `NodeGroups`, `FlexBodies`, `Contacters` are the PhysX bindings, registered
  via `PyImport_AppendInittab` wrappers at `0x3e67860` / `0x3e6a6ac`).
  A whole-word scan of `libGame.so` for `Config` returns only
  `Config/Built.version` (`0x5dc483`), `Config/` (`0x5e76b0`), `Config-`
  (`0x64539d`), the PhysX `Config` (`0x6c2b2e`) and two `CageResource.Config`
  symbols — **no file name**.
* **Known-plaintext handle:** `LocalData/Patch/TroyConfig/{Collision,Graphics}.bin`
  are the *same tagged binary config format* in **plaintext**
  (`u16 len + name + type_tag`, tags `s`/`v`/`p`/`M`). `Config`/`Config1`
  have the same `?? 5b …` header shape ⇒ the decrypted `Config` must parse as
  that format, which gives a validator for any candidate key (see §3.2).
* `ntes_gzailab::Encryptor` (ctor `0x3f74b24`) selects AES-128/192/256 from the
  first three chars of a key string (`"128"`/`"192"`/`"256"`) and then copies a
  **hard-coded key block** out of `.rodata`:

| rodata | bytes | use |
|---|---|---|
| `0xac0be0` | `110102530425660708893a8b5c0d0e4f` (+8 more bytes) | AES-128 / AES-192 key |
| `0x70b3f0` | `050102034455060728190a0b8c0d0e0f301312130455431758888a7b5c1d9e9f` | AES-256 key |
| `0x708410` | `9923722354654657280a4a6b9c0d6e1f` | second AES-128 candidate |

  (They are mangled FIPS-197 test vectors.)
  The only caller of `Encryptor::Decrypt` is
  `ntes_gzailab::MNNMaskComputer::Init` (`0x3f7b150`, PLT `0x5d06c30`),
  which builds the key string `"128"` inline (libc++ SSO: size byte `0x06`,
  data `"128"` at +1) — so these keys are **not** the Config keys.
* Brute force so far (all failed): AES-128/192/256 ECB/CBC/CTR/CFB/OFB with the
  three embedded keys and the canonical FIPS keys, zero/header IVs, IV-prefix
  layouts; RC4 with 510 harvested candidate keys and keystream drops; XOR/zlib/
  gzip/bz2/lzma transforms.
  Scripts: `analysis/try_config_keys.py`, `analysis/try_config_rc4.py`,
  `analysis/try_config_embedded_keys.py`, `analysis/try_config_aes_modes.py`,
  `analysis/config_xor_key.py`.

**Next attack:** find the code that opens `LocalData/Config` (the path must be
built at runtime — look for `fopen`/`std::ifstream` callers near the
`MChecker`/`MConfig` Cython code, and for the `Config`/`Config1` *module*
strings inside the `MConfig` Cython module at `0xa74976`), then read the exact
key/IV derivation. `MChecker` exposes `MConfig` and `MConfig` appears in the
MChecker string table at `0xa74976`, next to `/LocalData/Patch/Patch.mpkinfo`
(`0xa74951`) — i.e. `MConfig` is very likely the module that owns
`LocalData/Config*`.

**New attack surface (promising):** the plaintext key files
`Patch/0a/0a0ab8a4-…` and `Patch/0d/0d0ab9a4-…`
(§3.1) are 58-byte ASCII strings of the form `<uuid>-<ts>-<ts>`. Feed them
through `MImporter.gen_md5` (md5 slot `0x73cd168` + salt slot `0x73cd380`,
both loaded at `0x3a697ac`/`0x3a697a4`) and use the digest as the `Config`
key; validate with the `TroyConfig` tagged-format crib.

### 4.5 The `regular_encode` environment SDK (RESOLVED — it is **content moderation**, NOT the server list)

The `nos.gameyw.easebar.com/gameyw-gbox/regular_encode_*.json.one_z6` file was
downloaded (HTTP 200, 355,936 B, `application/octet-stream`) and its decoder
chain is now **fully mapped** from the Java side
(`decompiled/jadx/base/sources/com/netease/environment/`):

```
base64(text)  →  RC4(key)  →  LZMA (5-byte header + u64LE size)  →  JSON
```

| class | role |
|---|---|
| `OooO0oo/OooOO0O.java` (RC4Utils) | `OooO00o(byte[])` = LZMA-only; `OooO0O0(byte[], String key)` = **base64-decode → RC4 → LZMA → UTF-8 string**; `OooO0OO(byte[], String)` = **RC4 encrypt** (used to re-encrypt the file that is cached on disk) |
| `OooO0oo/OooOO0.java` (RC4) | classic RC4 KSA/PRGA; **key length must be 5…255** (`"Key length has to be between 5 and 255"`) |
| `OooO0OO/C6330OooO0Oo.java` (SdkData) | `OooO0Oo(str)` = game id, `OooO0o(str)` = **RC4 key** (`OooOO0()` returns it), `OooO0o0(str)` = signing secret |
| `OooO0Oo/C6331OooO00o.java` | downloads + parses the regular file |
| `OooO0oO/AsyncTaskC6334OooO00o.java` | async download; sets the `f2h` flag |
| `OooO0oo/C6341OooO0o0.java` | `sign(str, value, gameid, key)` |
| `OooO0oo/C6340OooO0Oo.java` | file names `<gameid>_regex.txt` / `<gameid>_temp.txt` |
| `EnvManager.java` | `initSDK(Context, str, str2, str3)` → `str` = game id, **`str2` = the RC4 key (lower-cased)**, `str3` = signing secret; `getSdkVersion() = "4.2.4"`; `DEFAULT_REGULAR_VERSION = "regular_encode_sdk_default_1690513256_dcc8caa8d81457e438b6ab311153d927"` |

Entry point: `com/netease/messiah/Channel.java:676`
`public void startEnvironment(String str, String str2, String str3)` →
`EnvManager.initSDK(this.m_activity, str, str2, str3)`.
The call is made **from native code**: `libGame.so` contains the string
`startEnvironment` at `0x652482` (loaded at `0x3114d88`); the wrapper at
`0x3114d40` does `GetStaticMethodID(env, cls, "startEnvironment", <sig>)` and
then invokes it with **three strings held in an 80-byte struct**
(`vtable`/`typeinfo` at `0x5e34520`, three `std::string`s at `+8 / +32 / +56`).

**⇒ This whole track is the NetEase “environment” (content-moderation) SDK.**
Its API surface is `EnvManager.reviewNickname` / `reviewWords` /
`reviewNicknameV2` / `reviewWordsV2` / `setExtraInfo` — it filters player
nicknames and chat text against a downloaded regex/pattern list.
**It is NOT the bootstrap server list** — so decrypting it will *not* yield
`server_list_host` / `cli_gateway`. (Earlier hypotheses that `regular_encode`
held the server list are therefore **withdrawn**.)

**Both encrypted artefacts are already on disk** (from the captured app data):

```
stock-files/com.netease.newspike.1/files/com/netease/environment/temp/g83naxx1ena_temp.txt    355,936 B  (downloaded file, == what we fetched)
stock-files/com.netease.newspike.1/files/com/netease/environment/file/g83naxx1ena_regex.txt  3,805,856 B  (base64(RC4(JSON,key)) — the re-encrypted local cache)
```

The native side supplies `str2` (the RC4 key) at runtime and it is **not** a
plain string in `libGame.so` (0 hits for `g83naxx1ena`, `g83naxx`, `easebar.com`,
`com.netease.newspike`, `bloodstrike` in the whole binary), and a 206,427-key
dictionary sweep of every printable string in `libGame.so` failed to crack it
(`analysis/crack_env_rc4.py`, validated against the LZMA header: props byte
< 225, dictionary size and the u64LE uncompressed length must both be
sane). ⇒ the key is derived at runtime from the encrypted Python/config layer.

---

## 5. Other engine facts

* `MChecker` (Cython) imports three sibling modules by name: **`MConfig`**,
  `MImporter`, `MPatch`, plus `MReloadImporter`; its string table also carries
  the struct format **`'=QH32sBBQ'`** — exactly the GUID record layout of
  `Patch.mpkinfo` (`u64`, `u16`, 32-byte MD5, `u8`, `u8`, `u64`), i.e. MChecker
  is the patch/MPK manager. `MConfig` is *not* one of the 4 Cython modules
  (MChecker, MGameBuildin, MImporter_py3, MLauncher) ⇒ it is an **encrypted
  plain-Python module** loaded through `MImporter` — the prime suspect for the
  owner of `LocalData/Config*`.
* Native (non-Cython) Python module names found next to the MLauncher strings
  (0x683b7c…): **`MLauncher.gen_md5`**, **`_lz4block`**, **`MAsyncore`**,
  `RegProduct`, `OpenWebView`, `SavePhotoToAlbum`, `IsInit`,
  `UnloadAnimations`, `SetEffectDebugOutput`, `PrintPlayingEffects`,
  `UnpinAllSkeletons`, `SoftChainProperty`, `SetMemoryWarnCallback`.
* `MChecker` API (Cython): `AddBatchPatchMpkEntry[ByKey]`, `AppLocalPathUtf8`,
  `ClearPatchMpkEntry`, `EnableCheck`, `FileExistInPackage/Patch`,
  `FileSizeInPatch`, `FileTimeInPatch`, `Filelist`, `GetRawDataInPackage/Patch`,
  `OpenFileDataInPackage/Patch`, `SetPatchMpkMode`, `SimplePatchMpk.*`,
  `MPK_INFO`, `MPK_DATA_SIZE`, `MPK_SUFFIX`, `/LocalData/Patch/Patch.mpkinfo`.
* MPK filesystem classes: `Messiah::MpkFileSystem`, `CusMpkFileSystem`,
  `PatchMpkFileSystem`, `RemoteMpkFileSystem`.
* Login glue: `Java_com_netease_messiah_Channel_NativeOnLogin` @ `0x31180b0`
  → closure helper `0x2b1b9bc` → reads `SdkMgr` properties (property-getter
  wrappers with RTTI words `0x20c`/`0x20d`).
* `libGame.so` contains **no hard-coded game-server IPs** (only 8 IP literals,
  all dummy/loopback). All servers come from the encrypted config / UniSDK
  HTTP-DNS.
* **Correction:** `gate.cc.163.com`, `audiouser.cc.163.com` and
  `get_ex_linkd` are **not** in `libGame.so` — they live in
  **`libAudioEngine.so`** (`decompiled/native/lib/arm64-v8a/libAudioEngine.so`).
  They are therefore *audio/SDK-telemetry* endpoints, **not** the game-session
  gate. The actual game gate host must come from the encrypted config.
* Native endpoints (in `libGame.so`): `https://statlog.cc.163.com/query`,
  `http://statlog.cc.netease.com/query`,
  `cc.fp.ps.netease.com` / `cc.devfp.ps.netease.com` (+ `*.easebar.com`
  mirrors), `HTTP/1.1 202 Accepted`, `HTTP/1.1 206 Partial Content`.
* UniSDK endpoints: `protocol.unisdk.easebar.com`, `nos.gameyw.easebar.com`,
  `notice.easebar.com`, `dns.update.easebar.com`,
  `mgbnaeast-g83naxx1ena.unisdk.easebar.com`,
  `mgbsdknaeast.matrix.easebar.com`,
  `sdkgate.pushv3.easebar.com:25004`, `appdump.nie.netease.com`.
* HTTP-DNS resolvers: mainland `103.71.201.4`, oversea `34.96.71.105`;
  the live resolver endpoint seen in the uniTrace log is
  `https://34.49.54.14/v2?domain=<host>`.
* `environment_preferences_config.xml` (shared_prefs) holds the concrete
  bootstrap URL for this build:
  `regex_file_url_g83naxx1ena = https://nos.gameyw.easebar.com/gameyw-gbox/regular_encode_g83naxx1ena_1793868663_fcd63733464e9c887288e34e89f7c2e0.json.one_z6`
  plus `drpf = drpf-dep87.proxima.nie.easebar.com`, `update_interval=3600000`,
  `task_timeout=3000`, `update_data_time=1794371582869`.
  ⚠ **Correction (see §4.5):** `regular_encode_*` is the **content-moderation
  regex/pattern list**, *not* the server list. The bootstrap server list must
  come from the encrypted `MConfig` / `LocalData/Config*` layer.
* `protocol_configs.xml` holds `protocol_modify#<md5>` timestamps plus
  quoted device/profile ids and `protocol_launch_accept=true`.
* `HTTPQ_PAY.xml` contains an `Authorization: Bearer <JWT>` (HS256,
  `sub = 1622853581_netease_global_win_163.com`, `exp=1794630793`).

---

## 6. Tooling built so far (all under `analysis/`)

```
extract_protos.py          # pull embedded FileDescriptorProtos out of libGame.so
protos/*.proto             # client_gate, common, gate_game, server_common
lz4_block.py               # pure-python LZ4 block decoder (returns bytes consumed)
mpk_extract.py             # global-offset aware MPK extractor + JSONL manifest
                           #   (now: chunk accounting, .MESSIAH support)
scan_mpk_blocks.py         # walk all LZ4 blocks of a patch mpk
scan_package_blocks.py     # same for Resources1.mpk
search_mpk_blocks.py       # grep decompressed blocks for python/keywords
scan_zlib_streams.py       # brute-force zlib/deflate stream finder
parse_mpkinfo.py           # Patch.mpkinfo parser (multi-layout)
parse_resources_mpkinfo.py # Resources.mpkinfo parser (+ MD5 trailer verify)
scan_patch_records.py      # brute-force record scanner
scan_plain_patch_records.py
sample_guid_payloads.py    # sample + fingerprint GUID payloads
find_messiah_magic.py      # locate .MESSIAH containers in the patch
dump_messiah_records.py    # dump the .MESSIAH records
parse_messiah_container.py # .MESSIAH kind-1/kind-2 parser
parse_resources1.py        # Resources1.mpk bundle/chunk walker
package_records.py         # NEW: rigorous Resources1.mpk record parser
                           #   (magic/desc/NNNN/ZZZ4 + LZ4 block length walker)
probe_multichunk.py        # verify single-chunk records
find_arm64_xrefs.py        # ADRP/ADD + ADRP/LDR xref finder
find_bl_sites.py           # BL call-site finder
find_cython_refs.py        # xrefs into the Cython string table
cython_string_slots.py     # recover Cython interned-string global slots
cython_slots2.py           # FIXED version (tracks ADRP page per register)
cython-string-slots2.txt   # 244 corrected interned-string slots
scan_globals_access.py     # ADRP+LDR/STR walker over the Cython global pages
serverlist/g83naxx1ena.list.json   # ★ RECOVERED SDK domain server list (32 domains)
serverlist/g83naxx1me.list.json    # MENA variant
ptr_index.py               # 8-byte in-image pointer index over data sections
find_frozen_modules.py     # hunt for a frozen-module table
find_python_modules.py     # PyImport_AppendInittab module table
scan_relocs.py / dump_sections.py
try_config_*.py / config_xor_key.py   # Config decryption campaigns
murmur3.py                 # MurmurHash3 x86_32 (seed 0) — digest0 of Resources.mpkinfo
package_index.py           # join Resources.mpkinfo + pack manifest
build_file_table.py        # ★ definitive name -> byte-range table (41,376 names, 0 ambiguous)
tagged_config.py           # parser for the tagged binary config grammar (s/i/(/{)
                            #   used by essential_py3 and TroyConfig/*.bin
essential/essential_py3.bin  # ★ extracted + MD5-verified package filelist blob
scan_globals_access.py     # ADRP+LDR/STR walker over the Cython global pages
                            #   (0x73cb000-0x73ce000) — found the salt object
crack_env_rc4.py           # RC4-key cracker for the environment SDK (LZMA-header oracle)
solve_mimporter_salt.py    # solve MImporter's XOR salt from (name -> guid) pairs
solve_mimporter_salt2.py   # bit-masked variant (allows forced UUID v4 bits)
```

## 7. Recommended next steps

0. **★ NEW — the *game* gate list (highest value, and now narrowly
   scoped)** — the SDK `.list` file (§1.2) is recovered, but the *game*
   server list is fetched from a host the native layer names
   `server_list_host` / `cli_gateway`, both of which are **never set in
   Java** ⇒ they come out of the encrypted `LocalData/Config`. Therefore
   item 1 below is now the critical path for *everything* (Config, Python
   modules, game gate list).
   *Auxiliary lead:* `com.netease.ntunisdk.base.ConstProp.ECHOES_SERVERLIST`
   ("ECHOES_SERVERLIST") is uploaded to the SDK telemetry endpoint as
   `server_list` — if we can make the client talk to that endpoint with a
   known project id, the echo payload would echo back the list host.

1. **Config (critical path)** — recover the `MImporter`/`MConfig` key
   derivation and apply it to `LocalData/Config`; validate against the
   `TroyConfig` tagged-format crib (§3.2) and the 21-byte `LuckyFile`
   crib (§4.3). Concretely: (a) the salt **value** lives in the
   module-state slot `0x73cd740` (written once at `0x3a5f5a4` by the helper
   call at `0x3a5f580`) — `0x73cce40` is merely the interned string
   `enumerate` (§3.6); (b) the `filename_encrypt` closure captures
   `value ^ 0x7f` at `0x3a68d88` — recovering *that* constant yields the
   salt directly; (c) run the `71ad02b5-…-1794371578-1794371578` seed
   through `gen_md5` (`0x3a69354–0x3a69a30`) and try the digest as the
   `Config` key under the cipher family that `decrypt_string`
   (`0x3a6d780–0x3a6d960`) uses; (d) the cipher is **position-stable with
   a global key** (§4.4) and the family magic is `bf 5b` — treat bytes
   0–1 as plaintext and attack from there.
   Correct slot addresses (see §3.6 for the correction): interned *name*
   slots `salt`=0x73cd380, `sdata`=0x73cd388, `self`=0x73cd390,
   `sep`=0x73cd3a0; module-state *value* slots `salt`=0x73cd7d8,
   `sdata`=0x73cd7e0, `self`=0x73cd7e8, `sep`=0x73cd7f0,
   `decrypt_string`=0x73ccdb0, `zlib`=0x73cd450.
2. **Bootstrap server list** — ~~the `regular_encode_*` file~~ is **content
   moderation** (§4.5), *not* the server list; the SDK **domain** list is
   now **RECOVERED** (§1.2). The real *game* list must come from
   `MConfig` / `LocalData/Config*`. Keep using the HttpDns API
   `https://34.49.54.14/v2?domain=<host>` to resolve the known CDN hosts
   (`g83-11/12/13.gph.easebar.com`, `nos.gameyw.easebar.com`) in the
   meantime.
3. **Encrypted module filenames** — fully disassemble the MImporter
   module-init at `0x39da500` (it fills the constant pointer table that holds
   `main` / `Script/Python` / `/Lib3`) and the `filename_encrypt` consumers
   (`0x3a5c4a4`, `0x3a5cb04`, `0x3a71d9c…0x3a71e70`) to derive the on-disk
   name of each encrypted `.py` module, then look those names up in
   `analysis/patch-records.jsonl` / `packagefilelist`.
   **New lever:** the `filename_encrypt` closure captures the constant
   `value ^ 0x7f` at `0x3a68d88` — recovering *that* constant yields the
   salt directly; a data-driven solve needs the *hashed input string* to be
   the full relative path (e.g. `Script/Python/<module>`), not the raw
   `dlcid_*` key (all 168 combinations in `analysis/solve_mimporter_salt2.py`
   failed).
4. **Resources1.mpk file bodies** — **SOLVED.** The file table is complete
   (§2.3): 41,376 names → byte ranges, 0 ambiguities, `essential_py3`
   extracted and MD5-verified. `flags = 0` does **not** mean “encrypted” — it
   is simply the *packed* form (ASTC/LZ4 pages) whose MD5 differs from the
   manifest's source-asset MD5.
5. **Transport** — now narrowed to a *runtime* decision in the encrypted
   Python layer (§1.1); once the Python is decrypted, look for
   `async_kcp_connection` vs `async_websocket_connection` instantiation and
   for `asiocore.set_kcp_vgate` / `set_kcp_vginfo`.
6. **Java side** — decompile the remaining dex files and
   `split_config.arm64_v8a.apk`; the writer of `server_list_host` /
   `cli_gateway` is probably in `com.netease.download.config.ConfigCore` or
   `com.netease.download.listener.*`, not in `KeyConst`.
7. **The `4!|{` filelist blob** — `MLauncher.MAGIC == "4!|{"` (literal at
   `0xa76f9a`). It is **not** on disk (the only `4!|{` byte sequence inside
   `Resources1.mpk` is the tail of the pack-manifest MD5 plus `!|{`).
   It is either downloaded at runtime or generated by the packer. Recovering
   it would give the authoritative `filepath / filesize / filemd5` list used
   for the package-vs-patch check.
8. **`decrypt_string` primitive** — the last blocker for everything
   (Python, `Config`). Attack surface: the consumer at `0x3a6d780–0x3a6d960`
   loads the `zlib` global at `0x3a6d904` and the `decrypt_string` global at
   `0x3a6d838`; `gen_md5` XORs a 64-bit constant into the digest
   (`eor x0, x8, x0 @ 0x3a69610`, constant read from `[x19+16]`).
9. **Bootstrap class** — disassemble `Messiah::PythonModule`
   (`StartModule`, `Start`, `Construct_on`) — it is the native code that
   installs the Python path (`Script/Python`, `/Lib3`) and therefore the
   place where the encrypted logic is rooted.
