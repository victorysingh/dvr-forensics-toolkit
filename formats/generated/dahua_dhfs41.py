# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import IntEnum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 11):
    raise Exception("Incompatible Kaitai Struct Python API: 0.11 or later is required, but you have %s" % (kaitaistruct.__version__))

class DahuaDhfs41(KaitaiStruct):
    """Documentation artifact, not the runtime parser (docs/TECH_STACK.md: Kaitai
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
    
    .. seealso::
       docs/DAHUA_DHFS.md; ffmpeg libavformat/dhav.c
    """

    class FrameType(IntEnum):
        audio = 240
        aux = 241
        b_frame = 251
        p_frame = 252
        i_frame = 253

    class RecordKind(IntEnum):
        empty = 0
        head = 1
        continuation = 2
        reserved = 254
    def __init__(self, _io, _parent=None, _root=None):
        super(DahuaDhfs41, self).__init__(_io)
        self._parent = _parent
        self._root = _root or self
        self._read()

    def _read(self):
        pass


    def _fetch_instances(self):
        pass
        _ = self.partition_table
        if hasattr(self, '_m_partition_table'):
            pass
            self._m_partition_table._fetch_instances()

        _ = self.partition_table_backup
        if hasattr(self, '_m_partition_table_backup'):
            pass
            self._m_partition_table_backup._fetch_instances()

        _ = self.superblock
        if hasattr(self, '_m_superblock'):
            pass
            self._m_superblock._fetch_instances()


    class ClusterRecord(KaitaiStruct):
        """OBSERVED. One 32-byte record per 2 MiB cluster. A recording is a head
        record plus a chain of continuations linked by `next`. On volume 1 of
        the observed disk: 513 heads, 114,550 continuations, 0 broken links.
        """
        def __init__(self, _io, _parent=None, _root=None):
            super(DahuaDhfs41.ClusterRecord, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.kind = KaitaiStream.resolve_enum(DahuaDhfs41.RecordKind, self._io.read_u1())
            self.channel = self._io.read_u1()
            self.count_or_seq = self._io.read_u2le()
            self.start = DahuaDhfs41.PackedDate(self._io, self, self._root)
            self.end = DahuaDhfs41.PackedDate(self._io, self, self._root)
            self.next = self._io.read_u4le()
            self.undecoded_10 = self._io.read_u4le()
            self.prev = self._io.read_u4le()
            self.head = self._io.read_u4le()
            self.undecoded_1c = self._io.read_u2le()
            self.undecoded_1e = self._io.read_u2le()


        def _fetch_instances(self):
            pass
            self.start._fetch_instances()
            self.end._fetch_instances()


    class DhavFrame(KaitaiStruct):
        """The video container. Frames carry no camera number (every camera
        writes channel 0), which is why carved footage outside the index has
        no camera. A frame is accepted only if the header checksum holds AND
        the trailer repeats the length.
        """
        def __init__(self, _io, _parent=None, _root=None):
            super(DahuaDhfs41.DhavFrame, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            if not self.magic == b"\x44\x48\x41\x56":
                raise kaitaistruct.ValidationNotEqualError(b"\x44\x48\x41\x56", self.magic, self._io, u"/types/dhav_frame/seq/0")
            self.type = KaitaiStream.resolve_enum(DahuaDhfs41.FrameType, self._io.read_u1())
            self.sub_type = self._io.read_u1()
            self.channel = self._io.read_u1()
            self.sub_number = self._io.read_u1()
            self.frame_number = self._io.read_u4le()
            self.frame_length = self._io.read_u4le()
            self.date = DahuaDhfs41.PackedDate(self._io, self, self._root)
            self.ms_clock = self._io.read_u2le()
            self.ext_length = self._io.read_u1()
            self.checksum = self._io.read_u1()
            self.extension = self._io.read_bytes(self.ext_length)
            self.payload = self._io.read_bytes(((self.frame_length - 24) - self.ext_length) - 8)
            self.trailer_magic = self._io.read_bytes(4)
            if not self.trailer_magic == b"\x64\x68\x61\x76":
                raise kaitaistruct.ValidationNotEqualError(b"\x64\x68\x61\x76", self.trailer_magic, self._io, u"/types/dhav_frame/seq/13")
            self.trailer_length = self._io.read_u4le()


        def _fetch_instances(self):
            pass
            self.date._fetch_instances()


    class PackedDate(KaitaiStruct):
        """PUBLISHED (ffmpeg dhav.c). Also used by the DHFS index. Recorder wall clock, zone unknown."""
        def __init__(self, _io, _parent=None, _root=None):
            super(DahuaDhfs41.PackedDate, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.raw = self._io.read_u4le()


        def _fetch_instances(self):
            pass

        @property
        def day(self):
            if hasattr(self, '_m_day'):
                return self._m_day

            self._m_day = self.raw >> 17 & 31
            return getattr(self, '_m_day', None)

        @property
        def hour(self):
            if hasattr(self, '_m_hour'):
                return self._m_hour

            self._m_hour = self.raw >> 12 & 31
            return getattr(self, '_m_hour', None)

        @property
        def minute(self):
            if hasattr(self, '_m_minute'):
                return self._m_minute

            self._m_minute = self.raw >> 6 & 63
            return getattr(self, '_m_minute', None)

        @property
        def month(self):
            if hasattr(self, '_m_month'):
                return self._m_month

            self._m_month = self.raw >> 22 & 15
            return getattr(self, '_m_month', None)

        @property
        def second(self):
            if hasattr(self, '_m_second'):
                return self._m_second

            self._m_second = self.raw & 63
            return getattr(self, '_m_second', None)

        @property
        def year(self):
            if hasattr(self, '_m_year'):
                return self._m_year

            self._m_year = (self.raw >> 26 & 63) + 2000
            return getattr(self, '_m_year', None)


    class PartitionEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(DahuaDhfs41.PartitionEntry, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.undecoded_00 = self._io.read_bytes(36)
            self.start_sector = self._io.read_u4le()
            self.high_28 = self._io.read_u4le()
            self.sector_count = self._io.read_u4le()
            self.high_30 = self._io.read_u4le()
            self.undecoded_34 = self._io.read_bytes(12)


        def _fetch_instances(self):
            pass
            _ = self.volume
            if hasattr(self, '_m_volume'):
                pass
                self._m_volume._fetch_instances()

            _ = self.volume_header_backup
            if hasattr(self, '_m_volume_header_backup'):
                pass


        @property
        def volume(self):
            if hasattr(self, '_m_volume'):
                return self._m_volume

            if self.sector_count != 0:
                pass
                io = self._root._io
                _pos = io.pos()
                io.seek(self.start_sector * 512 + 17408)
                self._m_volume = DahuaDhfs41.VolumeHeader(self.start_sector * 512, io, self, self._root)
                io.seek(_pos)

            return getattr(self, '_m_volume', None)

        @property
        def volume_header_backup(self):
            """OBSERVED. Matched the primary header on volume 1."""
            if hasattr(self, '_m_volume_header_backup'):
                return self._m_volume_header_backup

            if self.sector_count != 0:
                pass
                io = self._root._io
                _pos = io.pos()
                io.seek(self.start_sector * 512 + 33792)
                self._m_volume_header_backup = io.read_bytes(512)
                io.seek(_pos)

            return getattr(self, '_m_volume_header_backup', None)


    class PartitionTable(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(DahuaDhfs41.PartitionTable, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.header = self._io.read_bytes(64)
            self.entries = []
            for i in range(15):
                self.entries.append(DahuaDhfs41.PartitionEntry(self._io, self, self._root))



        def _fetch_instances(self):
            pass
            for i in range(len(self.entries)):
                pass
                self.entries[i]._fetch_instances()



    class Superblock(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(DahuaDhfs41.Superblock, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            if not self.magic == b"\x44\x48\x46\x53":
                raise kaitaistruct.ValidationNotEqualError(b"\x44\x48\x46\x53", self.magic, self._io, u"/types/superblock/seq/0")
            self.version = (KaitaiStream.bytes_terminate(self._io.read_bytes(8), 0, False)).decode(u"ASCII")
            self.undecoded_0c = self._io.read_bytes(20)
            self.uuid = (KaitaiStream.bytes_terminate(self._io.read_bytes(64), 0, False)).decode(u"ASCII")


        def _fetch_instances(self):
            pass
            _ = self.boot_marker
            if hasattr(self, '_m_boot_marker'):
                pass


        @property
        def boot_marker(self):
            """OBSERVED. AA 55 AA 55."""
            if hasattr(self, '_m_boot_marker'):
                return self._m_boot_marker

            _pos = self._io.pos()
            self._io.seek(500)
            self._m_boot_marker = self._io.read_bytes(4)
            self._io.seek(_pos)
            return getattr(self, '_m_boot_marker', None)


    class VolumeHeader(KaitaiStruct):
        def __init__(self, vol_start, _io, _parent=None, _root=None):
            super(DahuaDhfs41.VolumeHeader, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self.vol_start = vol_start
            self._read()

        def _read(self):
            self.undecoded_00 = self._io.read_bytes(8)
            self.undecoded_08 = self._io.read_u4le()
            self.undecoded_0c = self._io.read_u4le()
            self.earliest_recording = DahuaDhfs41.PackedDate(self._io, self, self._root)
            self.latest_recording = DahuaDhfs41.PackedDate(self._io, self, self._root)
            self.undecoded_18 = self._io.read_u4le()
            self.undecoded_1c = self._io.read_bytes(16)
            self.sector_size = self._io.read_u4le()
            self.sectors_per_cluster = self._io.read_u4le()
            self.undecoded_34 = self._io.read_u4le()
            self.first_data_cluster = self._io.read_u4le()
            self.undecoded_3c = self._io.read_u4le()
            self.undecoded_40 = self._io.read_u4le()
            self.index_start_sector = self._io.read_u4le()
            self.undecoded_48 = self._io.read_u4le()
            self.cluster_capacity = self._io.read_u4le()


        def _fetch_instances(self):
            pass
            self.earliest_recording._fetch_instances()
            self.latest_recording._fetch_instances()
            _ = self.cluster_table
            if hasattr(self, '_m_cluster_table'):
                pass
                for i in range(len(self._m_cluster_table)):
                    pass
                    self._m_cluster_table[i]._fetch_instances()



        @property
        def cluster_size(self):
            if hasattr(self, '_m_cluster_size'):
                return self._m_cluster_size

            self._m_cluster_size = self.sectors_per_cluster * self.sector_size
            return getattr(self, '_m_cluster_size', None)

        @property
        def cluster_table(self):
            if hasattr(self, '_m_cluster_table'):
                return self._m_cluster_table

            io = self._root._io
            _pos = io.pos()
            io.seek(self.vol_start + self.index_start_sector * 512)
            self._m_cluster_table = []
            for i in range(self.cluster_capacity):
                self._m_cluster_table.append(DahuaDhfs41.ClusterRecord(io, self, self._root))

            io.seek(_pos)
            return getattr(self, '_m_cluster_table', None)


    @property
    def partition_table(self):
        """OBSERVED. Primary copy."""
        if hasattr(self, '_m_partition_table'):
            return self._m_partition_table

        _pos = self._io.pos()
        self._io.seek(15360)
        self._raw__m_partition_table = self._io.read_bytes(1024)
        _io__raw__m_partition_table = KaitaiStream(BytesIO(self._raw__m_partition_table))
        self._m_partition_table = DahuaDhfs41.PartitionTable(_io__raw__m_partition_table, self, self._root)
        self._io.seek(_pos)
        return getattr(self, '_m_partition_table', None)

    @property
    def partition_table_backup(self):
        """OBSERVED. Byte-identical to the primary on the observed disk; a difference is itself a finding."""
        if hasattr(self, '_m_partition_table_backup'):
            return self._m_partition_table_backup

        _pos = self._io.pos()
        self._io.seek(31744)
        self._raw__m_partition_table_backup = self._io.read_bytes(1024)
        _io__raw__m_partition_table_backup = KaitaiStream(BytesIO(self._raw__m_partition_table_backup))
        self._m_partition_table_backup = DahuaDhfs41.PartitionTable(_io__raw__m_partition_table_backup, self, self._root)
        self._io.seek(_pos)
        return getattr(self, '_m_partition_table_backup', None)

    @property
    def superblock(self):
        if hasattr(self, '_m_superblock'):
            return self._m_superblock

        _pos = self._io.pos()
        self._io.seek(0)
        self._m_superblock = DahuaDhfs41.Superblock(self._io, self, self._root)
        self._io.seek(_pos)
        return getattr(self, '_m_superblock', None)


