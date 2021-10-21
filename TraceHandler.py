import struct
from collections import namedtuple
from typing import Dict
import numpy as np


class HeaderHandler:
    header_format = [
        # Type: int->I, short->h, unsigned char(byte)-> B, char[]->bytes
        # Consistency: whether to tolerate with different values when merging headers
        # tag  Name  M/O Type Length De   Consistency  Desc
        [0x41, 'NT', 1,  'I',   4,    0,           0, "Number of traces"],
        [0x42, 'NS', 1,  'I',   4,    0,           1, "Number of samples per trace"],
        [0x43, 'SC', 1,  'B',   1,    0,           1, "Sample Coding"],
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
    _Item = namedtuple("Item", ["tag", "name", "mo", "type", "length", "value", "consist", "descr"])

    def __init__(self) -> None:
        header_item = [self._Item._make(item) for item in self.header_format]
        self.header_item = {item.tag:item for item in header_item}

        self.global_header_dict = self.__make_empty()

        self.StartMarker = b"\x5f\x00"

    def __getitem__(self, attribute):
        for item in self.header_format:
            if item[1] == attribute:
                return self.global_header_dict[item[0]]

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
    
    # utility for making an empty header dictionary
    def __make_empty(self):
        return {tag:self.header_item[tag].value for tag in self.header_item}
    
    # utility for removing useless items from a header dictionary
    def __trim(self, header_dict:Dict):
        for tag in header_dict:
            if header_dict[tag] != self.header_item[tag].value or self.header_item[tag].mo:
                continue
            else:
                header_dict.pop(tag)
        return header_dict

    # parse header from input bytes string
    def parse(self, bytestring:bytes):
        header_dict = self.__make_empty()
        length = len(bytestring)
        cur = 0
        while cur < length:
            tag = bytestring[cur]
            cur += 1
            if tag in self.header_item:
                if self.header_item[tag].type == bytes:
                    length = bytestring[cur]
                    cur += 1
                    header_dict[tag] = bytestring[cur:cur+length]
                    cur += length
                else:
                    assert bytestring[cur] == self.header_item[tag].length
                    cur += 1
                    header_dict[tag] = struct.unpack(self.header_item[tag].type, bytestring[cur:cur+length])[0]
            elif tag == 0x5f:
                assert bytestring[cur] == 0
                cur += 1
                break
            else:
                return None, cur-1
        return header_dict, cur
    
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
        SC_tag = 0x43
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

        if self.global_header_dict[SC_tag]:
            assert encode == self.global_header_dict[SC_tag]
        else:
            self.global_header_dict[SC_tag] = encode
    
    def set_title(self, title):
        if isinstance(title, str):
            title = title.encode()
        if isinstance(title, bytes):
            self.global_header_dict[0x46] = title
    
    def __attribute_setter(self, attribute, value):
        if attribute == 'SC':
            self.__set_code(value)
        elif attribute == 'NT':
            raise ValueError("Can't set number of traces. \
                This attribute should be updated automatically.")
        else:
            for item in self.header_format:
                if item[1] == attribute:
                    tag = item[0]
                    self.global_header_dict[tag] = value
    
    def set_header_manually(self, **kwargs):
        for attr in kwargs:
            for tag in self.header_item:
                if self.header_item[tag].name == attr:
                    self.__attribute_setter(attr, kwargs[attr])
            else:
                raise ValueError("Unknown header attribute {}".format(attr))

    def increment_number_of_traces(self, incr):
        NT_tag = 0x41
        self.global_header_dict[NT_tag] += incr


class TraceHandler:
    def __init__(self, with_header=False) -> None:
        self.header_handler = HeaderHandler()
        self.filelist = []
        self.buffer = b''
        self.transformer = lambda x: x
        self.with_header = with_header
        self.file_format = 'binary' # or 'npy', if 'npy', then with_header should be False
    
    def set_attribute(self, **kwargs):
        self.header_handler.set_header_manually(**kwargs)

    def generate_header_bytes(self):
        return self.header_handler.build()
    
    def set_header(self, header):
        if isinstance(header, bytes):
            header_dict, cur = self.header_handler.parse(header)
            if header_dict:
                self.header_handler.update(header_dict)
            else:
                ValueError("Invalid header tag at position {}".format(cur))
        elif isinstance(header, dict):
            self.header_handler.update(header)
        else:
            ValueError("Unrecognized header format")
    
    def append_file(self, filename):
        if self.file_format == 'npy':
            # Parse from numpy file
            raise NotImplementedError
        else:
            self.filelist.append(filename)

    def transform(self, transformer):
        self.transformer = transformer

    def save2trs(self, output:str, crypto_data_getter=None, chunksize=1024*1024*4):
        '''
        crypto_data_getter(cnt, i, j) return cryptodata that's to 
        be embedded into the final trs file for j-th trace of i-th
        inputted trace file, with cnt-th trace processed in total.
        '''
        out = open(output, 'wb')
        out.write(self.header_handler.build())
        trace_cnt = 0
        for i, file in enumerate(self.filelist):
            with open(file, b'rb') as tracefile:
                _, offset = self.__parse_header_from_file(filename)
                tracefile.seek(offset, 0) # skip header
                j = 0
                while True:
                    one_trace = tracefile.read(self.header_handler['NS'])
                    j += 1
                    if not one_trace: break
                    assert len(one_trace) == self.header_handler['NS']
                    if self.header_handler['DS'] and crypto_data_getter:
                        crypto_data = crypto_data_getter(trace_cnt, i, j)
                        assert len(crypto_data) == self.header_handler['DS']
                    self.buffer += crypto_data + one_trace
                    self.__write_buffer(out, chunksize)
        self.__write_buffer(out, chunksize, clear=True)
        out.close()
    
    def __write_buffer(self, outfile, chunksize, clear=False):
        while len(self.buffer) >= chunksize or (clear and self.buffer):
            outfile.write(self.buffer[:chunksize])
            self.buffer = self.buffer[chunksize:]

    def generate_header(self):
        if self.with_header:
            for filename in self.filelist:
                header, _ = self.__parse_header_from_file(filename)
                self.header_handler.update(header)
            self.summary()
        else:
            for filename in self.filelist:
                _, trace_number = self.get_binary_file_points_and_traces(filename)
                self.header_handler.increment_number_of_traces(trace_number)
    
    def __parse_header_from_file(self, file):
        with open(file, 'rb') as f:
            broad_header = f.read(2000) # max header length is less than 2000
        header_dict, offset = self.header_handler.parse(broad_header)
        if header_dict:
            return header_dict, offset
        else:
            raise ValueError("Header confilict at tag {}! before: {}; this: {}.".format(*offset))
    
    def toNumpy(self):
        raise NotImplementedError
    
    def summary(self):
        if self.header_handler.global_header_dict:
            print("Merging {} traces with {} points each".format(
                self.header_handler['NT'],
                self.header_handler['NS']
            ))
    
    def get_binary_file_points_and_traces(self, filename:str):
        import os
        file_size = os.path.getsize(filename)
        point_size = self.header_handler['SC'] & 0x0f # in bytes
        if file_size % point_size:
            print("Possibly wrong data type")
        point_number = file_size / point_size
        if point_number % self.header_handler['NS']:
            print("Possibly wrong data type")
        trace_number = point_number / self.header_handler['NS']
        return point_number, trace_number