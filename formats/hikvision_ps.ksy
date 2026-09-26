meta:
  id: hikvision_ps
  title: Hikvision recording as MPEG-2 Program Stream, with "HK" stream-map descriptors
  endian: be
doc: |
  Documentation artifact (docs/TECH_STACK.md: Kaitai as documentation;
  recover/pscarve.py is the hand-written reader). Not yet machine-checked
  with kaitai-struct-compiler.

  The container is ISO/IEC 13818-1 (STANDARD). The "HK" descriptors are
  Hikvision's private data (OBSERVED on the team's second drive, Seagate
  ST1000VX005 s/n Z9C2632A, where a Dahua-family recorder had reformatted the
  drive and Hikvision footage survived underneath).

  Observed stream: one pack per video frame (25 fps), a Program Stream Map
  before each keyframe (1 per second), H.264 at 960x576 (the 0x42 video
  descriptor holds 0x03C0 x 0x0240).

  On that drive the primary master sector was overwritten, but two HIKBTREE
  copies survived near the end of the disk; `hikbtree_record` below is their
  leaf record (OBSERVED, 922 records). parsers/hikbtree.py reads it.
seq:
  - id: packs
    type: pack
    repeat: eos
types:
  pack:
    seq:
      - id: start_code
        contents: [0x00, 0x00, 0x01, 0xba]
      - id: scr
        size: 6
        doc: STANDARD. 33-bit SCR base (90 kHz) + 9-bit extension, with marker bits. A relative clock, not a date.
      - id: mux_rate
        size: 3
      - id: stuffing
        type: u1
        doc: low 3 bits = number of stuffing bytes that follow
      - id: stuffing_bytes
        size: stuffing & 0x07
      - id: packets
        type: pes
        repeat: until
        repeat-until: _io.eof or _io.pos + 4 > _io.size
        doc: |
          Until the next pack header. The carver accepts a pack only when
          these length fields land EXACTLY on the next 00 00 01 BA.
  pes:
    seq:
      - id: start_code
        contents: [0x00, 0x00, 0x01]
      - id: stream_id
        type: u1
        doc: STANDARD. 0xBC stream map, 0xE0-0xEF video, 0xC0-0xDF audio, 0xBD private.
      - id: length
        type: u2
      - id: body
        size: length
        type:
          switch-on: stream_id
          cases:
            0xbc: program_stream_map
  program_stream_map:
    seq:
      - id: version
        size: 2
      - id: info_length
        type: u2
      - id: descriptors
        size: info_length
        type: descriptors
      - id: es_map_length
        type: u2
      - id: es_entries
        size: es_map_length
        type: es_entries
  descriptors:
    seq:
      - id: items
        type: descriptor
        repeat: eos
  descriptor:
    seq:
      - id: tag
        type: u1
      - id: length
        type: u1
      - id: body
        size: length
        type:
          switch-on: tag
          cases:
            0x40: hk_time_descriptor
  hk_time_descriptor:
    doc: |
      OBSERVED. The recorder's clock at this stream map (i.e. at the keyframe
      that follows). Checked three ways on real footage: equal to the clock
      burned into the decoded frame to the second; +1 s per stream map;
      spans the same interval as the pack clock (290 s). Recorder-local time,
      zone not stored.
    seq:
      - id: magic
        contents: HK
      - id: version
        size: 2
        doc: OBSERVED 01 00.
      - id: year
        type: u1
        doc: years since 2000
      - id: packed
        type: u4
      - id: tail
        size-eos: true
        doc: OBSERVED 00 FF FF FF; undecoded.
    instances:
      month:
        value: packed >> 28
      day:
        value: (packed >> 23) & 0x1f
      hour:
        value: (packed >> 18) & 0x1f
      minute:
        value: (packed >> 12) & 0x3f
      second:
        value: (packed >> 6) & 0x3f
      low_bits:
        value: packed & 0x3f
        doc: OBSERVED always 32; undecoded.
  hikbtree_record:
    doc: OBSERVED. 48-byte leaf record of the HIKBTREE index.
    seq:
      - id: marker
        contents: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
      - id: undecoded_08
        size: 9
      - id: channel
        type: u1
        doc: 1..N; 255 = an initialised, never-used block
      - id: undecoded_12
        size: 6
      - id: start
        type: u4le
        doc: seconds since 1970 on the recorder's local clock (equals the HK time of the footage)
      - id: end
        type: u4le
      - id: block_offset
        type: u8le
        doc: byte offset of the 1 GiB data block (base + N GiB; base 0x4C5E000 observed)
      - id: undecoded_28
        type: u4le
        doc: 0x20 observed
      - id: undecoded_2c
        type: u4le
        doc: small counter, meaning not established
  es_entries:
    seq:
      - id: items
        type: es_entry
        repeat: eos
  es_entry:
    seq:
      - id: stream_type
        type: u1
        doc: STANDARD. 0x1B H.264, 0x24 H.265, 0x90 G.711 A-law (common on DVRs).
      - id: stream_id
        type: u1
      - id: info_length
        type: u2
      - id: info
        size: info_length
        doc: OBSERVED. 0x42 video descriptor (width 0x03C0, height 0x0240 seen), 0x44 undecoded.
