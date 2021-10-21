import struct
from collections import namedtuple
from typing import Dict
import numpy as np
import re
import os

class TraceHandler:
    header_format = [
        # Type: int->I, short->h, unsigned char(byte)-> B, char[]->bytes
        # tag  Name  M/O Type Length De   Consistency  Desc
        [0x41, 'NT', 1,  'I',   4,    0,           0, "Number of traces"],
        [0x42, 'NS', 1,  'I',   4,    0,           1, "Number of samples per trace"],
        [0x43, 'SC', 1,  'B',   1,    0,           1, "Sample Encoding"],
        [0x44, 'DS', 0,  'h',   2,    0,           1, "Length of cryptographic data included in trace"],
        [0x45, 'TS', 0,  'B',   1,    0,           0, "Title space reserved per trace"],
        [0x46, 'GT', 0,bytes,  -1, None,           0, "Global trace title"],
        [0x47, 'DC', 0,bytes,  -1, None,           0, "Description"],
        [0x48, 'XO', 0,  'I',   4,    0,           0, "Offset in X-axis for trace representation"],
        [0x49, 'XL', 0,bytes,  -1, None,           0, "Label of X-axis"],
        [0x4A, 'YL', 0,bytes,  -1, None,           0, "Label of Y-axis"],
        [0x4B, 'XS', 0,  'f',   4,    1,           1, "Scale value for X-axis"],
        [0x4C, 'YS', 0,  'f',   4,    1,           1, "Scale value for Y-axis"],
        [0x4D, 'TO', 0,  'I',   4,    0,           0, "Trace offset for displaying trace numbers"],
        [0x4E, 'LS', 0,  'B',   1,    0,           1, "Logarithmic scale"],
        #[0x5f, 'TB', 1, None,   0,    0,           1, "Trace block marker: an empty TLV that marks the end of the header"]
    ]
    Item = namedtuple("Item", ["tag", "name", "mo", "type", "length", "value", "consist", "descr"])

    def __init__(self) -> None:
        self.header_item = [self.Item._make(item) for item in self.header_format]
        self.default_header = {item.tag:item for item in self.header_item}

        self.global_header_dict = self.make_empty_header_dict()

        self.StartMarker = b"\x5f\x00"

        self.global_header:bytes = None

    def build_header_from_dict(self, header_dict) -> bytes:
        header_dict = self.trim_header_dict(header_dict)
        header  = b''
        for item in self.header_item:
            if item.tag in header_dict:
                header += struct.pack('B', item.tag)
                header += struct.pack('B', item.length)
                if item.type == bytes:
                    header += header_dict[item.tag]
                else:
                    header += struct.pack(item.type, header_dict[item.tag])
            elif item.mo:
                raise ValueError("Mandatory field {} missing".format(item.name))
            else:
                continue

        header += self.StartMarker
        return header
    
    def make_empty_header_dict(self):
        return {item.tag:item.value for item in self.header_item}

    def trim_header_dict(self, header_dict:Dict):
        for tag in header_dict:
            if header_dict[tag] != self.default_header[tag].value:
                continue
            else:
                header_dict.pop(tag)
        return header_dict

    def parse_header(self, bytestring:bytes):
        header_dict = self.make_empty_header_dict()
        length = len(bytestring)
        cur = 0
        while cur < length:
            tag = bytestring[cur]
            cur += 1
            if tag in self.default_header:
                if self.default_header[tag].type == bytes:
                    length = bytestring[cur]
                    cur += 1
                    header_dict[tag] = bytestring[cur:cur+length]
                    cur += length
                else:
                    assert bytestring[cur] == self.default_header[tag].length
                    cur += 1
                    header_dict[tag] = struct.unpack(self.default_header[tag].type, bytestring[cur:cur+length])[0]
            elif tag == 0x5f:
                assert bytestring[cur] == 0
                cur += 1
                break
            else:
                return None, -1
        return header_dict, cur
    
    @classmethod
    def fromFile(cls, file, header=True):
        cls.__init__()
        return cls
            
                


