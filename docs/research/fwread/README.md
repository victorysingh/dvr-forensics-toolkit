# Re-deriving the Uniview and TP-Link layouts from their firmware

`plugins/uniview.py` and `plugins/tplink.py` cite a firmware function for
every field. This folder holds the two small readers used to read those
functions. Anyone can re-run them on the same public firmware and check each
claim. They disassemble and nothing else: no firmware code is run.

Needs `pip install capstone pyelftools` (not needed by the tool itself).

## The firmware

| Vendor | Image | File read | SHA-256 |
|---|---|---|---|
| Uniview | `NVR301_04LS3_W_General-B3612.1.21.220408.zip` (download.aras.nl/Video/Uniview/Recorders/Firmware/) → `Program.bin` → SquashFS | `/driverfile/comm.ko` | `56b84ede4893acf0c2f5fffe6e2235f2b0b9a6ac9dee55166449ec53043ac3fc` |
| TP-Link | archive.org `TP-Link_VIGINVR1008HV2_240119_cc1d1` → `nvr1008hv2_en_1_0_7_up_boot_24011951953-signed.bin` → SquashFS at 0x18A600 | `/usr/lib/liblayouthddb.so` | `df6c5bd2518b908a879de8908b675337d3fe2a3c2bb1410f04e11dad20c3b169` |
| TP-Link | (same) | `/usr/lib/libsqlite3.so.0.8.6` | `4754d86ab6476fd4b8997de9e3c52b0dc94209bb936a2234934e8de8d8c00ea0` |
| TP-Link | (same) | `/usr/lib/libstorage.so` | `be790e1f72fc13e219714b7b7c43ef38dc4f3fe778b5719b8b21f070c8ae71fb` |
| TP-Link | (same) | `/bin/nvrcore` | `49a5b249481783ad09d89fbb979c36971bfd4f94994220b2f79b340da1361c32` |

How they were fetched and unpacked is in `../datasets.md`, which also has
the other firmware hunted for.

## The readers

- `ko.py` reads a kernel module (a relocatable ARM ELF). It labels each
  literal-pool word with the string or symbol its relocation points at, and
  each call with its target.
- `so.py` reads a shared library (Thumb-2, position-independent). It resolves
  `ldr rX, [pc]` + `add rX, pc` string loads and PLT calls.

```bash
python ko.py comm.ko func UBS_MT_PrintSuper     # one function, annotated
python ko.py comm.ko find "Capacity"            # functions that load a string
python so.py liblayouthddb.so syms rawDiskLayout
```

- `sofia.py` reads Qualvision's statically linked `Sofia` (ARM, ELF at file
  offset 0x200, loaded at 0x10000): where a debug string is used, and the
  code around it, each literal load labelled.

| Qualvision (Godrej) firmware | File read | SHA-256 |
|---|---|---|
| `NVR401L-4P4.20240531.zip` (homaxi.com, SHA-256 `fe10f5381258146817c1663d10207ec2971eefb890e2485d437804d99172a80a`) → `.upf` → `usr.ubiimg` (UBIFS, LZO) | `/Sofia` (from `Sofia.lzma`) | `eb9e9e1d5ff48f519eb5c9fef1f8f140006976f0a4462799273524625ec2944b` |

## Where each Uniview structure comes from (`comm.ko`)

| Structure | Function(s) | What to look for |
|---|---|---|
| Superblock fields and offsets | `UBS_MT_PrintSuper` | each field's name string loaded next to `ldr rN, [r5, #off]` |
| Superblock magic, version, CRC | `UBS_RS_SuperInit`, `UBS_RS_ChkSb` | `0x20131031`, `0x2000`; `crc16(0, sb, 0x10000)` with +8 zeroed |
| Tail copy | `UBS_RS_OpenSuper` | offset = capacity − 0x10000 |
| Units, abstract size | `UBS_RS_GetKeyParam`, `UBS_RS_CalcUnits2`, `UBS_RS_GetAbsLen2` | 256 MiB units; ⌈units/496⌉ × 64 KiB |
| Abstract groups and entries | `UBS_RS_SetupAbstNode2`, `UBS_RS_CheckUnit2`, `UBS_RS_CrcCheck2`, `UBS_RS_DbSbToAbs`, `UBS_RecDbSbToBrief` | 4 KiB groups, entry k at +0x80·(k+1), CRC-16 in the first u16 |
| Data block address | `UBS_Open` | `DzPos + (blk << 28)` |
| Data zone limit | `UBS_RS_SuperCheck2` | DzPos ≤ 0x10000000 |
| Block header | `UBS_MT_DispDiskDbSuper`, `UBS_DB_GetRecDbSb4`, `UBS_DB_ChkSb4` | 0x5050, v0x400, fields by name |
| Block internals | `UBS_RecDb_Ver4_Init` | index at +0x2000, 0x3F00 entries |
| GOP index entry | `UBS_DB_SetSubIndx4`, `UBS_DB_MT_DispIndxZone` | page offset and page count at +0x12 and +0x10 |
| GOP and packets | `UBS_DB_RecoveryFromDataBlk`, `UBS_DB_ChkIGrpHdr`, `UBS_DB_ChkIGrpInfo`, `UBS_DB_ChkPktHdr`, `UBS_MT_PrintGopPkt`, `UBS_DB_ChkVideoPkt` | 0x2006, 0x1357, 0x6002, 0x6003; next packet at pktlen + 0x1C |

## Where each TP-Link structure comes from

| Structure | Library, function | What to look for |
|---|---|---|
| Format sector | `liblayouthddb.so` `rawDiskLayout_diskInfoFormatCheck` | read 0x200 at 0x20000000, loop to 0x231FFFFF; `calculate_CRC32(buf, 0x1FC)` vs `[buf+0x1FC]`; `strncmp(tag, 0x2C)` |
| Database-area sizes | `rawDiskLayout_determineDefDBSizeByDiskSize` | 64 / 128 / 256 MiB |
| TpFile header | `libsqlite3.so` `sqliteTpFileInit`, `getTpFileHeadSize` | "TP-Link format1" copied to the header; size 0x200 |
| Key slots | `libsqlite3.so` `getTpFileKey`, `setTpFileKey` | big-endian reads (`rev`) at +0x20/+0x24/+0x28 |
| Encryption | `libsqlite3.so` `CodecAES`, `sqlite3_key`; `liblayouthddb.so` `set_key_to_db`, `key_info_init_v1` | the default key string in `key_info_init_v1` |
| Tables | `liblayouthddb.so` strings | `CREATE TABLE IF NOT EXISTS %s(...)` and the `t*Info` names |
| Format sector's other fields | `rawDiskLayout_diskInfoFormat` | `movw 0x5450` to +0x80; the disk size to +0x84; 0x40000000 to +0x8C; 0x8000000 to +0x90 |
| Database-area record | `rawDiskLayout_resetDBAreaInfo`, `rawDiskLayout_DBAreaInfoInit` | first extent 0x23201000 (bytes 00 10 20 23), length area − 0x1000 at +8; read from disk-info start + 0x400, journal + 0x600; `calculate_CRC32(rec, 0x1FC)` vs +0x1FC |
| Data-zone start | `rawDiskLayout_resetDBAreaInfo` ("disk%d start_addr"), run at mount by `layout_fs_init_resource_v1` (`io_init`, then the PLT stub of `resetDBAreaInfo`) | 0x23200000, plus the area size twice |
| Zone address | `rawDiskLayout_io_read` | `uxth zone`; `umlal` with 0x40000000; plus `getDataZoneStartAddr`; the log "zone_id %u addr %lld ... rawDiskAddr" |
| Zone GOP index | `write_raw_disk_data_index`, `insert_gop_index_v1`, `get_gop_index_v1` | 0x50 per entry, (offset + count) × 0x50 ≤ 0x100000; the stores to entry −0x50 … −0x20; the reader's filter on +0x04 (event) and +0x18 (stream) and its log "st%lld et%lld offset%d" |
| GOP length | `layout_read_data_by_index` | "start get data len ... goplen" from the struct's +8, which `get_gop_index_v1` fills from entry +0x20 |
| Frames in a GOP | `nvrcore` `web_parse_gop_data_frm` (ET_EXEC, read with `exe.py`); `libstorage.so` `extend_iter_i_frame_in_gop`, `extend_get_frame_type` | next frame = header + 0x20 + align8(length at +8); bytes +0x20..+0x23 must be 00 00 00 01; codec at +0x10; key frame when +0x0D is 0 or 2; the key-frame table's 8-byte entries at the GOP's end |

`exe.py` is `so.py` for a fixed-address executable such as `nvrcore`: a
literal that points at a string is shown as the string. `rng.py`
disassembles an address range, for a static function such as
`libstorage.so`'s GOP writer at 0x9e94.

Still not recovered: the frame header's other bytes, the index entry's
32-bit fields at +0x24 and +0x28, and audio.

## Where each Qualvision (Godrej) structure comes from (`Sofia`)

Godrej's SeeThru cloud portal drives Qualvision's `/tdkcgi` API, and
`Sofia` implements it, so a SeeThru recorder runs this software
(`../vendor_formats.md`). Addresses are virtual addresses.

| Structure | Function (found by its string) | What to look for |
|---|---|---|
| Disk head | `IDiskExt::CheckHead` 0x954e64 (`sofia.py Sofia str "int IDiskExt::CheckHead()"`) | `QVEX` = 0x58455651 at +0; 0x10000 at +4; +8 and +0xC against the disk object's +0x44/+0x48; the three bounds checks on +0x10..+0x1C |
| Frame head | `CheckFrameHead` 0x989858 | `u32[+0] & 0xFFFFFF == 0x10000`; `(type + 0x20) & 0xFF <= 0x0B`; length at +4 |
| Head size | `LoadFrameHead` 0x98a164 | reads 0x14 bytes into the object at +0xD4 |
| Payload, next frame | `ReadPacket` 0x98a320 | allocates length + 0x14, reads length bytes from +0x14; next = here + 0x14 + length (0x98a728) |
| Frame time | `CHOTUpload::OpenFile` 0x309610 (`str "openfile frame head time"`) | the debug print's shifts on the u32 at +8 (sec, min, hour, day, month, year-2000) and the u16 at +0xC (ms) |

Not recovered, and so not used by the plugin: the VIDEO/PIC index blocks and
the per-channel HM time index (which name a frame's camera), the meaning of
frame types 0xE0-0xEB, and the six bytes at +0x0E of a frame head.
