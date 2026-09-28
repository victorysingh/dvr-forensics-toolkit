meta:
  id: dahua_dhfs41
  title: Dahua DHFS 4.1 DVR filesystem (as observed on a CP Plus unit's drive)
  endian: le
  file-extension: dd
doc: |
  Documentation artifact, not the runtime parser (docs/TECH_STACK.md: Kaitai
  as documentation; parsers/dahua.py is hand-written against this layout).
  Compiled with kaitai-struct-compiler 0.11.0 and checked field by field
  against parsers/dahua.py by validate/ksy_check.py (VALIDATION_REPORT.md
  section 9a) - so far on synthetic disks; the real image is still to run.

  Every field's `doc` says what it rests on:
    OBSERVED  - read off real media we hold: Seagate SkyHawk ST1000VX013
                s/n WWD4A3NX from a CP Plus DVR (first 20 GiB image sha256
                c4098d59...f610); status spec_only, not byte-matched to a
                recorder export
    PUBLISHED - ffmpeg libavformat/dhav.c (DHAV frame container)
  Offsets present on disk whose meaning is not established are named
  `undecoded_XX` and deliberately left uninterpreted.

  What this file cannot express: the data area's base offset. Cluster N of a
  volume lives at data_base + N * cluster_size, and no header field on the
  observed disk yields data_base directly (0x95E000 on volume 1). The parser
  calibrates it by voting cluster-aligned I-frames against index time
  windows; see docs/DAHUA_DHFS.md section 5.
doc-ref: docs/DAHUA_DHFS.md; ffmpeg libavformat/dhav.c
instances:
  superblock:
    pos: 0
    type: superblock
  partition_table:
    pos: 0x3c00
    size: 0x400
    type: partition_table
    doc: OBSERVED. Primary copy.
  partition_table_backup:
    pos: 0x7c00
    size: 0x400
    type: partition_table
    doc: OBSERVED. Byte-identical to the primary on the observed disk; a difference is itself a finding.
types:
  superblock:
    seq:
      - id: magic
        contents: DHFS
        doc: OBSERVED; also dvrdecode.
      - id: version
        size: 8
        type: strz
        encoding: ASCII
        doc: OBSERVED. "4.1".
      - id: undecoded_0c
        size: 0x14
      - id: uuid
        size: 64
        type: strz
        encoding: ASCII
        doc: OBSERVED. "uuid:{b7656fca-9c42-ebce-bf64-f44c71a8c1b0}" on the observed disk.
    instances:
      boot_marker:
        pos: 0x1f4
        size: 4
        doc: OBSERVED. AA 55 AA 55.
  partition_table:
    seq:
      - id: header
        size: 0x40
      - id: entries
        type: partition_entry
        repeat: expr
        repeat-expr: 15
        doc: OBSERVED. Entries end at the first with sector_count 0; 4 on the observed 1 TB disk.
  partition_entry:
    seq:
      - id: undecoded_00
        size: 0x24
      - id: start_sector
        type: u4
        doc: OBSERVED. Volume start in 512-byte sectors; the four starts tile the disk with no gaps.
      - id: high_28
        type: u4
        doc: OBSERVED zero. Non-zero would suggest 64-bit fields on larger disks.
      - id: sector_count
        type: u4
        doc: OBSERVED. start + count < next start.
      - id: high_30
        type: u4
        doc: OBSERVED zero.
      - id: undecoded_34
        size: 0x0c
    instances:
      volume:
        if: sector_count != 0
        io: _root._io
        pos: start_sector * 512 + 0x4400
        type: volume_header(start_sector * 512)
      volume_header_backup:
        if: sector_count != 0
        io: _root._io
        pos: start_sector * 512 + 0x8400
        size: 512
        doc: OBSERVED. Matched the primary header on volume 1.
  volume_header:
    params:
      - id: vol_start
        type: u8
    seq:
      - id: undecoded_00
        size: 8
      - id: undecoded_08
        type: u4
        doc: 10 on the observed disk; meaning not established.
      - id: undecoded_0c
        type: u4
        doc: 85 on the observed disk.
      - id: earliest_recording
        type: packed_date
        doc: OBSERVED. Equals the earliest head record's start.
      - id: latest_recording
        type: packed_date
        doc: OBSERVED. Within 2 s of the latest head record's end.
      - id: undecoded_18
        type: u4
      - id: undecoded_1c
        size: 0x10
      - id: sector_size
        type: u4
        doc: OBSERVED. 512.
      - id: sectors_per_cluster
        type: u4
        doc: OBSERVED. 0x1000, i.e. 2 MiB clusters; matches the frame layout.
      - id: undecoded_34
        type: u4
      - id: first_data_cluster
        type: u4
        doc: OBSERVED. Equals the number of leading reserved (0xFE) records.
      - id: undecoded_3c
        type: u4
      - id: undecoded_40
        type: u4
      - id: index_start_sector
        type: u4
        doc: OBSERVED. Cluster table start, volume-relative (0xBB -> 0x17600).
      - id: undecoded_48
        type: u4
      - id: cluster_capacity
        type: u4
        doc: OBSERVED. Cluster slots; volume size / 2 MiB, rounded down.
    instances:
      cluster_size:
        value: sectors_per_cluster * sector_size
      cluster_table:
        io: _root._io
        pos: vol_start + index_start_sector * 512
        type: cluster_record
        repeat: expr
        repeat-expr: cluster_capacity
  cluster_record:
    doc: |
      OBSERVED. One 32-byte record per 2 MiB cluster. A recording is a head
      record plus a chain of continuations linked by `next`. On volume 1 of
      the observed disk: 513 heads, 114,550 continuations, 0 broken links.
    seq:
      - id: kind
        type: u1
        enum: record_kind
      - id: channel
        type: u1
        doc: OBSERVED. Camera as an ASCII digit, '0' = first camera; 0xFE on reserved records.
      - id: count_or_seq
        type: u2
        doc: OBSERVED. Head - number of continuations; continuation - sequence number.
      - id: start
        type: packed_date
        doc: OBSERVED. Frame dates in the cluster fall inside [start, end].
      - id: end
        type: packed_date
        doc: OBSERVED. On a head, the file's end, on the hour.
      - id: next
        type: u4
        doc: OBSERVED. Next cluster in the chain; 0 terminates.
      - id: undecoded_10
        type: u4
        doc: 512-4096 on heads; meaning not established.
      - id: prev
        type: u4
        doc: OBSERVED. Previous cluster.
      - id: head
        type: u4
        doc: OBSERVED. Head cluster of this file.
      - id: undecoded_1c
        type: u2
      - id: undecoded_1e
        type: u2
  dhav_frame:
    doc: |
      The video container. Frames carry no camera number (every camera
      writes channel 0), which is why carved footage outside the index has
      no camera. A frame is accepted only if the header checksum holds AND
      the trailer repeats the length.
    seq:
      - id: magic
        contents: DHAV
        doc: PUBLISHED.
      - id: type
        type: u1
        enum: frame_type
        doc: PUBLISHED.
      - id: sub_type
        type: u1
      - id: channel
        type: u1
        doc: OBSERVED 0 for every camera.
      - id: sub_number
        type: u1
      - id: frame_number
        type: u4
        doc: PUBLISHED. Per-stream counter, one sequence per frame kind.
      - id: frame_length
        type: u4
        doc: PUBLISHED. Whole frame, header and trailer included.
      - id: date
        type: packed_date
        doc: PUBLISHED. Recorder wall clock, no zone.
      - id: ms_clock
        type: u2
        doc: PUBLISHED. Millisecond clock, wraps at 65536.
      - id: ext_length
        type: u1
        doc: PUBLISHED.
      - id: checksum
        type: u1
        doc: OBSERVED. Sum of header bytes 0x00-0x16, mod 256. Not in ffmpeg.
      - id: extension
        size: ext_length
        doc: PUBLISHED tags. 0x80 width/8, height/8; 0x81 codec (0x0C H.265, 0x02/0x08 H.264), fps; 0x83 audio.
      - id: payload
        size: frame_length - 24 - ext_length - 8
        doc: Annex-B H.264/H.265 for video frames.
      - id: trailer_magic
        contents: dhav
        doc: PUBLISHED.
      - id: trailer_length
        type: u4
        doc: PUBLISHED. Repeats frame_length.
  packed_date:
    doc: PUBLISHED (ffmpeg dhav.c). Also used by the DHFS index. Recorder wall clock, zone unknown.
    seq:
      - id: raw
        type: u4
    instances:
      second:
        value: raw & 0x3f
      minute:
        value: (raw >> 6) & 0x3f
      hour:
        value: (raw >> 12) & 0x1f
      day:
        value: (raw >> 17) & 0x1f
      month:
        value: (raw >> 22) & 0x0f
      year:
        value: ((raw >> 26) & 0x3f) + 2000
enums:
  record_kind:
    0x00: empty
    0x01: head
    0x02: continuation
    0xfe: reserved
  frame_type:
    0xfd: i_frame
    0xfc: p_frame
    0xfb: b_frame
    0xf0: audio
    0xf1: aux
