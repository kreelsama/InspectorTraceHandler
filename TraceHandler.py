import struct
from collections import namedtuple
import numpy as np
import re
import os

class TraceHandler:
    header_format = [
        # tag  Name  M/O Type Length De   Consistency  Desc
        [0x41, 'NT', 1,  'I',   4,    0,           0, "Number of traces"],
        [0x42, 'NS', 1,  'I',   4,    0,           1, "Number of samples per trace"],
        [0x43, 'SC', 1,  'b',   1,    0,           1, "Sample Encoding"],
        [0x44, 'DS', 0,  'h',   2,    0,           1, "Length of cryptographic data included in trace"],
        [0x45, 'TS', 0,  'b',   1,    0,           0, "Title space reserved per trace"],
        [0x46, 'GT', 0,bytes,  -1, None,           0, "Global trace title"],
        [0x47, 'DC', 0,bytes,  -1, None,           0, "Description"],
        [0x48, 'XO', 0,  'I',   4,    0,           0, "Offset in X-axis for trace representation"],
        [0x49, 'XL', 0,bytes,  -1, None,           0, "Label of X-axis"],
        [0x4A, 'YL', 0,bytes,  -1, None,           0, "Label of Y-axis"],
        [0x4B, 'XS', 0,  'f',   4,    1,           1, "Scale value for X-axis"],
        [0x4C, 'YS', 0,  'f',   4,    1,           1, "Scale value for Y-axis"],
        [0x4D, 'TO', 0,  'I',   4,    0,           0, "Trace offset for displaying trace numbers"],
        [0x4E, 'LS', 0,  'b',   1,    0,           1, "Logarithmic scale"],
        [0x5f, 'TB', 1, None,   0,    0,           1, "Trace block marker: an empty TLV that marks the end of the header"]
    ]
    Item = namedtuple("Item", ["tag", "name", "mo", "type", "length", "value", "consist", "descr"])
    def __init__(self) -> None:
        self.header_item = [self.Item._make(item) for item in self.header_format]
        self.global_header_dict = {item.tag:item.value for item in self.header_item}
        # 0x41
        self.number_of_traces = 0 
        # 0x42
        self.number_of_samples_per_trace = 0
        # 0x43
        self.sample_coding:bytes = b''
        # 0x44
        self.len_crypto_data = 0
        # 0x46
        self.trace_title:bytes = None
        # 0x47
        self.description:bytes = None
        # 0x48
        self.Xoffset = None
        # 0x49
        self.Xlabel:bytes = None
        # 0x4a
        self.Ylabel:bytes = None
        # 0x4b
        self.Xscale = None
        # 0x4c
        self.Yscale = None
        # 0x4d
        self.TraceOffsetforDisplay = None
        # 0x4e
        self.Logscale:bytes = None
        # 0x5f
        self.StartMarker = b"\x5f\x00"

        self.global_header:bytes = None

        
    
    def build_header(self) -> bytes:
        header  = b''
        header += b"\x41\x04" + struct.pack('I', self.number_of_traces)
        header += b"\x42\x04" + struct.pack('I', self.number_of_samples_per_trace)
        header += b"\x43\x01" + self.sample_coding
        if self.len_crypto_data:
            header += b"\x44\x02" + struct.pack('h', self.len_crypto_data)
        if self.trace_title:
            header += b"\x45\x01" + struct.pack('B', 0)
            header += b"\x46" + struct.pack('B', len(self.trace_title)) + self.trace_title
        if self.description:
            header += b"\x45" + struct.pack('B', len(self.description)) + self.description
        if self.Xoffset:
            header += b"\x48\x04" + struct.pack('B', self.Xoffset)
        if self.Xlabel:
            header += b"\x49" + struct.pack('B', len(self.Xlabel)) + self.Xlabel
        if self.Ylabel:
            header += b"\x4a" + struct.pack('B', len(self.Ylabel)) + self.Ylabel
        if self.Xscale:
            header += b"\x4b\x04" + struct.pack('f', self.Xscale)
        if self.Yscale:
            header += b"\x4c\x04" + struct.pack('f', self.Yscale)
        if self.TraceOffsetforDisplay:
            header += b'\x4d\x04' + struct.pack('I', self.TraceOffsetforDisplay)
        if self.Logscale:
            assert len(self.Logscale) == 1
            header += b'\x4e\x01' + self.Logscale
        header += self.StartMarker
        return header
    
    def parse_header(self, bytestring:bytes):
        header_dict = {
            "NT":0,"NS":0,"SC":b'',"DS":0,
            "TS":None,"GT":None,"DC":None,"XO":None,
            "XL":None,"YL":None,"XS":None,"YS":None,
            "TO":None,"LS":None,"TB":None
        }
        length = len(bytestring)
        cur = 0
        while cur < length:
            cur_byte = bytestring[cur]
            cur += 1
            if cur_byte == 0x41:
                assert bytestring[cur] == 0x04
                cur += 1
                header_dict["NT"] = struct.unpack('I', bytestring[cur:cur+4])[0]
                cur += 4
            if cur_byte == 0x42:
                assert bytestring[cur] == 0x04
                cur += 1
                header_dict["NS"] = struct.unpack('I', bytestring[cur:cur+4])[0]
                cur += 4
            if cur_byte == 0x43:
                assert bytestring[cur] == 0x01
                cur += 1
                header_dict["SC"] = bytestring[cur:cur+1]
                cur += 1
            if cur_byte == 0x44:
                assert bytestring[cur] == 0x02
                cur += 1
                header_dict["DS"] = struct.unpack('h', bytestring[cur:cur+4])[0]
                cur += 4
            if cur_byte == 0x45:
                assert bytestring[cur] == 0x01
                cur += 1
                header_dict["TS"] = bytestring[cur:cur+1]
                cur += 1
            if cur_byte == 0x46:
                l = bytestring[cur]
                cur += 1
                header_dict["GT"] = bytestring[cur, cur+l]
                cur += l
            
                


