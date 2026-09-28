# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 11):
    raise Exception("Incompatible Kaitai Struct Python API: 0.11 or later is required, but you have %s" % (kaitaistruct.__version__))

class HikvisionPs(KaitaiStruct):
    """Documentation artifact (docs/TECH_STACK.md: Kaitai as documentation;
    recover/pscarve.py is the hand-written reader). Compiled with
    kaitai-struct-compiler 0.11.0 and checked against the hand-written reader
    by validate/ksy_check.py (VALIDATION_REPORT.md section 9a) - so far on
    synthetic streams; the real drive is still to run.
    
    The stream is read as a flat run of start-code units: a pack header
    (00 00 01 BA) is one unit, and each PES packet after it another, until the
    next pack header. (The first version nested packets inside packs and read
    them to the end of the stream - it compiled, but failed on the first
    stream it was given.)
    
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
    """
    def __init__(self, _io, _parent=None, _root=None):
        super(HikvisionPs, self).__init__(_io)
        self._parent = _parent
        self._root = _root or self
        self._read()

    def _read(self):
        self.units = []
        i = 0
        while not self._io.is_eof():
            self.units.append(HikvisionPs.Unit(self._io, self, self._root))
            i += 1



    def _fetch_instances(self):
        pass
        for i in range(len(self.units)):
            pass
            self.units[i]._fetch_instances()


    class Descriptor(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(HikvisionPs.Descriptor, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.tag = self._io.read_u1()
            self.length = self._io.read_u1()
            _on = self.tag
            if _on == 64:
                pass
                self._raw_body = self._io.read_bytes(self.length)
                _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
                self.body = HikvisionPs.HkTimeDescriptor(_io__raw_body, self, self._root)
            else:
                pass
                self.body = self._io.read_bytes(self.length)


        def _fetch_instances(self):
            pass
            _on = self.tag
            if _on == 64:
                pass
                self.body._fetch_instances()
            else:
                pass


    class Descriptors(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(HikvisionPs.Descriptors, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.items = []
            i = 0
            while not self._io.is_eof():
                self.items.append(HikvisionPs.Descriptor(self._io, self, self._root))
                i += 1



        def _fetch_instances(self):
            pass
            for i in range(len(self.items)):
                pass
                self.items[i]._fetch_instances()



    class EsEntries(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(HikvisionPs.EsEntries, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.items = []
            i = 0
            while not self._io.is_eof():
                self.items.append(HikvisionPs.EsEntry(self._io, self, self._root))
                i += 1



        def _fetch_instances(self):
            pass
            for i in range(len(self.items)):
                pass
                self.items[i]._fetch_instances()



    class EsEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(HikvisionPs.EsEntry, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.stream_type = self._io.read_u1()
            self.stream_id = self._io.read_u1()
            self.info_length = self._io.read_u2be()
            self.info = self._io.read_bytes(self.info_length)


        def _fetch_instances(self):
            pass


    class HikbtreeRecord(KaitaiStruct):
        """OBSERVED. 48-byte leaf record of the HIKBTREE index."""
        def __init__(self, _io, _parent=None, _root=None):
            super(HikvisionPs.HikbtreeRecord, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.marker = self._io.read_bytes(8)
            if not self.marker == b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF":
                raise kaitaistruct.ValidationNotEqualError(b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", self.marker, self._io, u"/types/hikbtree_record/seq/0")
            self.undecoded_08 = self._io.read_bytes(9)
            self.channel = self._io.read_u1()
            self.undecoded_12 = self._io.read_bytes(6)
            self.start = self._io.read_u4le()
            self.end = self._io.read_u4le()
            self.block_offset = self._io.read_u8le()
            self.undecoded_28 = self._io.read_u4le()
            self.undecoded_2c = self._io.read_u4le()


        def _fetch_instances(self):
            pass


    class HkTimeDescriptor(KaitaiStruct):
        """OBSERVED. The recorder's clock at this stream map (i.e. at the keyframe
        that follows). Checked three ways on real footage: equal to the clock
        burned into the decoded frame to the second; +1 s per stream map;
        spans the same interval as the pack clock (290 s). Recorder-local time,
        zone not stored.
        """
        def __init__(self, _io, _parent=None, _root=None):
            super(HikvisionPs.HkTimeDescriptor, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(2)
            if not self.magic == b"\x48\x4B":
                raise kaitaistruct.ValidationNotEqualError(b"\x48\x4B", self.magic, self._io, u"/types/hk_time_descriptor/seq/0")
            self.version = self._io.read_bytes(2)
            self.year = self._io.read_u1()
            self.packed = self._io.read_u4be()
            self.tail = self._io.read_bytes_full()


        def _fetch_instances(self):
            pass

        @property
        def day(self):
            if hasattr(self, '_m_day'):
                return self._m_day

            self._m_day = self.packed >> 23 & 31
            return getattr(self, '_m_day', None)

        @property
        def hour(self):
            if hasattr(self, '_m_hour'):
                return self._m_hour

            self._m_hour = self.packed >> 18 & 31
            return getattr(self, '_m_hour', None)

        @property
        def low_bits(self):
            """OBSERVED always 32; undecoded."""
            if hasattr(self, '_m_low_bits'):
                return self._m_low_bits

            self._m_low_bits = self.packed & 63
            return getattr(self, '_m_low_bits', None)

        @property
        def minute(self):
            if hasattr(self, '_m_minute'):
                return self._m_minute

            self._m_minute = self.packed >> 12 & 63
            return getattr(self, '_m_minute', None)

        @property
        def month(self):
            if hasattr(self, '_m_month'):
                return self._m_month

            self._m_month = self.packed >> 28
            return getattr(self, '_m_month', None)

        @property
        def second(self):
            if hasattr(self, '_m_second'):
                return self._m_second

            self._m_second = self.packed >> 6 & 63
            return getattr(self, '_m_second', None)


    class PackHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(HikvisionPs.PackHeader, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.scr = self._io.read_bytes(6)
            self.mux_rate = self._io.read_bytes(3)
            self.stuffing = self._io.read_u1()
            self.stuffing_bytes = self._io.read_bytes(self.stuffing & 7)


        def _fetch_instances(self):
            pass


    class Pes(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(HikvisionPs.Pes, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.length = self._io.read_u2be()
            _on = self._parent.stream_id
            if _on == 188:
                pass
                self._raw_body = self._io.read_bytes(self.length)
                _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
                self.body = HikvisionPs.ProgramStreamMap(_io__raw_body, self, self._root)
            else:
                pass
                self.body = self._io.read_bytes(self.length)


        def _fetch_instances(self):
            pass
            _on = self._parent.stream_id
            if _on == 188:
                pass
                self.body._fetch_instances()
            else:
                pass


    class ProgramStreamMap(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(HikvisionPs.ProgramStreamMap, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.version = self._io.read_bytes(2)
            self.info_length = self._io.read_u2be()
            self._raw_descriptors = self._io.read_bytes(self.info_length)
            _io__raw_descriptors = KaitaiStream(BytesIO(self._raw_descriptors))
            self.descriptors = HikvisionPs.Descriptors(_io__raw_descriptors, self, self._root)
            self.es_map_length = self._io.read_u2be()
            self._raw_es_entries = self._io.read_bytes(self.es_map_length)
            _io__raw_es_entries = KaitaiStream(BytesIO(self._raw_es_entries))
            self.es_entries = HikvisionPs.EsEntries(_io__raw_es_entries, self, self._root)
            self.crc32 = self._io.read_u4be()


        def _fetch_instances(self):
            pass
            self.descriptors._fetch_instances()
            self.es_entries._fetch_instances()


    class Unit(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(HikvisionPs.Unit, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.start_code = self._io.read_bytes(3)
            if not self.start_code == b"\x00\x00\x01":
                raise kaitaistruct.ValidationNotEqualError(b"\x00\x00\x01", self.start_code, self._io, u"/types/unit/seq/0")
            self.stream_id = self._io.read_u1()
            _on = self.stream_id
            if _on == 186:
                pass
                self.body = HikvisionPs.PackHeader(self._io, self, self._root)
            else:
                pass
                self.body = HikvisionPs.Pes(self._io, self, self._root)


        def _fetch_instances(self):
            pass
            _on = self.stream_id
            if _on == 186:
                pass
                self.body._fetch_instances()
            else:
                pass
                self.body._fetch_instances()



