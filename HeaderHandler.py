import struct
from collections import namedtuple
from typing import Dict
import numpy as np

header_format = [
    # Type: int->I, short->h, unsigned char(byte)-> B, char[]->bytes
    # Consistency: whether to tolerate with different values when merging headers
    # tag  Name M/O Type Length Default   Consistency  Desc
    [0x41, 'NT', 1,  'I',   4,        0,           0, "Number of traces"],
    [0x42, 'NS', 1,  'I',   4,        0,           1, "Number of samples per trace"],
    [0x43, 'SC', 1,  'B',   1,        0,           1, "Sample Coding"],
    [0x44, 'DS', 0,  'h',   2,        0,           1, "Length of cryptographic data included in trace"],
    [0x45, 'TS', 0,  'B',   1,        0,           0, "Title space reserved per trace"],
    [0x46, 'GT', 0,bytes,  -1,     None,           0, "Global trace title"],
    [0x47, 'DC', 0,bytes,  -1,     None,           0, "Description"],
    [0x48, 'XO', 0,  'I',   4,        0,           0, "Offset in X-axis for trace representation"],
    [0x49, 'XL', 0,bytes,  -1,     None,           0, "Label of X-axis"],
    [0x4A, 'YL', 0,bytes,  -1,     None,           0, "Label of Y-axis"],
    [0x4B, 'XS', 0,  'f',   4,        1,           1, "Scale value for X-axis"],
    [0x4C, 'YS', 0,  'f',   4,        1,           1, "Scale value for Y-axis"],
    [0x4D, 'TO', 0,  'I',   4,        0,           0, "Trace offset for displaying trace numbers"],
    [0x4E, 'LS', 0,  'B',   1,        0,           1, "Logarithmic scale"],
    #[0x5f, 'TB', 1, None,   0,    0,           1, "Trace block marker: an empty TLV that marks the end of the header"]
]
_Item = namedtuple("Item", ["tag", "name", "mo", "type", "length", "value", "consist", "descr"])

class HeaderHandler:
    def __init__(self) -> None:
        header_item = [_Item._make(item) for item in header_format]
        self.header_item = {item.tag:item for item in header_item}

        self.global_header_dict = None

        self.StartMarker = b"\x5f\x00"

    def __getitem__(self, attribute):
        for item in header_format:
            if item[1] == attribute:
                return self.global_header_dict[item[0]]

    def __bool__(self):
        if self.global_header_dict:
            return True
        else:
            return False
    
    # utility for making an empty header dictionary
    def __make_empty(self):
        return {tag:self.header_item[tag].value for tag in self.header_item}
    
    # utility for removing useless items from a header dictionary
    def __trim(self, header_dict:Dict):
        new_header = {}
        for tag in header_dict:
            if header_dict[tag] != self.header_item[tag].value or self.header_item[tag].mo:
                new_header[tag] = header_dict[tag]
            else:
                continue
        return new_header

    # build a header from header dictionary, return header bytes
    def build(self, header_dict=None) -> bytes:
        if not header_dict:
            header_dict = self.global_header_dict
        if not header_dict:
            ValueError("Can not build from empty header")
        header_dict = self.__trim(header_dict)
        header  = b''
        for tag in self.header_item:
            item = self.header_item[tag]
            if tag in header_dict:
                header += struct.pack('B', tag)
                if item.type == bytes:
                    header += struct.pack('B', len(header_dict[tag]))
                    header += header_dict[tag]
                else:
                    header += struct.pack('B', item.length)
                    header += struct.pack(item.type, header_dict[tag])
            elif item.mo:
                raise ValueError("Mandatory field {} missing".format(item.name))
            else:
                continue

        header += self.StartMarker
        return header
    
    # parse header from input bytes string
    def parse(self, bytestring:bytes):
        header_dict = self.__make_empty()
        length_all = len(bytestring)
        cur = 0
        while cur < length_all:
            tag = bytestring[cur]
            cur += 1
            length = bytestring[cur]
            if tag in self.header_item:
                if self.header_item[tag].type == bytes:
                    cur += 1
                else:
                    assert length == self.header_item[tag].length
                    cur += 1
                    header_dict[tag] = struct.unpack(
                        self.header_item[tag].type, 
                        bytestring[cur:cur+length]
                        )[0]
                cur += length
            elif tag == 0x5f:
                assert bytestring[cur] == 0
                cur += 1
                break
            else:
                print(tag)
                return None, cur-1
        return header_dict, cur
    
    # This utility can be further improved to reduce IO afford
    def parse_file(self, fname:str):
        with open(fname, 'rb') as IO:
            broad_header = IO.read(2000)
        return self.parse(broad_header)

    # input multiple headers, check if they can merge
    # can: return merged header. cannot: return false
    def merge(self, *headers):
        if len(headers) == 1 :
            return headers[0]
        merged_header = headers[0]
        for header in headers[1:]:
            for tag in header:
                if tag not in merged_header:
                    merged_header[tag] = header[tag]
                elif merged_header[tag] == header[tag]:
                    continue
                elif tag == 0x41 : # accumulated number of traces
                    merged_header[tag] += header[tag]
                elif not self.header_item[tag].consist:
                    merged_header[tag] = header[tag] # override
                else:
                    return False, (self.header_item[tag].name, merged_header[tag], header[tag])
        return True, merged_header

    def update(self, header_dict):
        if self.global_header_dict:
            success, merged = self.merge(self.global_header_dict, header_dict)
            if success:
                self.global_header_dict = merged
            else:
                raise ValueError("Header confilict at tag {}! before: {}; this: {}.".format(*merged))
        else:
            self.global_header_dict = header_dict
    
    def __set_code(self, dtype):
        encode = 0
        if dtype == 'int8' or dtype == 'byte':
            encode  = 0x01
        elif dtype == 'int16':
            encode  = 0x02
        elif dtype == 'int32' or dtype == 'int' or dtype == np.dtype('int32'):
            encode  = 0x04
        elif dtype == 'float' or dtype in \
            [np.dtype('float8'), np.dtype('float16'), np.dtype('float32'), np.dtype('float64')]:
            encode  = 0x14
        else:
            ValueError("Unrecognized dtype:{}".format(dtype))

        if self['SC']:
            assert encode == self['SC']
        else:
            SC_tag = 0x43
            self.global_header_dict[SC_tag] = encode

    def set_title(self, title):
        if isinstance(title, str):
            title = title.encode()
        if isinstance(title, bytes):
            self.global_header_dict[0x46] = title
    
    def __attribute_setter(self, attribute, value):
        if not self.global_header_dict:
            self.global_header_dict = self.__make_empty()
        if attribute == 'SC':
            self.__set_code(value)
        elif attribute == 'NT':
            raise ValueError("Can't set number of traces. \
                This attribute should be updated automatically.")
        else:
            for item in header_format:
                if item[1] == attribute:
                    tag = item[0]
                    self.global_header_dict[tag] = value
    
    def set_header_manually(self, **kwargs):
        for attr in kwargs:
            for tag in self.header_item:
                if self.header_item[tag].name == attr:
                    self.__attribute_setter(attr, kwargs[attr])
                    break
            else:
                raise ValueError("Unknown header attribute {}".format(attr))

    def increment_number_of_traces(self, incr):
        NT_tag = 0x41
        self.global_header_dict[NT_tag] += incr
    
    @property
    def crypto_length(self):
        return self['DS']
    
    @property
    def sample_length(self):
        return self['SC'] & 0xf
    
    @property
    def sample_coding(self):
        if self['SC']>>8:
            return 'float'
        else:
            return 'int'
    
    @property
    def number_of_traces(self):
        return self['NT']
    
    @property
    def samples_per_trace(self):
        return self['NS']
    
    @property
    def single_trace_byte_length(self):
        return self.samples_per_trace * self.sample_length
    
    @property
    def trace_interval(self):
        return self.single_trace_byte_length + self.crypto_length