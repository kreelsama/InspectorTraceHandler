import struct
import numpy as np
from .TraceHandler import HeaderHandler as inspector_header

# This class can only process SINGLE Inspector file with header
class InspectorFileDataLoader:    
    def __init__(self, fileinput=None, with_header=False, *args, **kargs) -> None:
        self.header_handler = inspector_header()
        if with_header:
            self.header, self.start_offset = self.header_handler.parse_file(fileinput)
            print(self.header, self.start_offset)
            self.header_handler.update(self.header)
            self.io = open(fileinput, 'rb')
            self.support_data = np.zeros(shape=(
                self.header_handler.number_of_traces, self.header_handler.crypto_length
                ), dtype=np.dtype('uint8'))
            self.__zero_offset()
            self.prepare(*args, **kargs)
        else:
            raise NotImplementedError("planning")
        self.cur = 0
        self.mask = None
    
    def __len__(self):
        return self.header_handler.number_of_traces
    
    # Using this attribute beautifies code
    @property
    def traces(self):
        return self
    
    def __zero_offset(self):
        self.io.seek(self.start_offset, 0)
        self.cur = 0

    def __forward(self, nbytes=0):
        self.io.seek(nbytes, 1)

    def __rewind(self, nbytes=0):
        self.io.seek(-nbytes, 1)

    def __next_position(self):
        self.__forward(self.header_handler.trace_interval)
    
    def __ith(self, i):
        self.io.seek((i - self.cur) * self.header_handler.trace_interval, 1)
        self.cur = i

    def __read(self, nbytes=None):
        r = self.io.read(nbytes)
        if nbytes:
            self.__rewind(nbytes)
        else:
            self.__zero_offset()
        return r

    def __read_samples(self, nsamples=0):
        return self.__read(nsamples * self.header_handler.sample_length)

    def __forward_samples(self, nsamples=0):
        return self.__forward(nsamples * self.header_handler.sample_length)
    
    def __rewind_samples(self, nsamples=0):
        return self.__rewind(nsamples * self.header_handler.sample_length)

    def prepare(self, cryptolen=0):
        pass

    def __prepare_crypto_data(self):
        self.__zero_offset()
        for idx in range(self.header_handler.number_of_traces):
            one = self.__read(self.header_handler.crypto_length)
            self.support_data[idx] = list(one)
            self.__next_position()
        self.__zero_offset()
        return self.support_data

    @property
    def crypto_data(self):
        return self.support_data
    
    def __del__(self):
        if not self.io.closed:
            self.io.close()
        
    def __getitem__(self, index):
        data = []
        if not isinstance(index, (tuple, int, slice)):
            raise IndexError("Unsupported Trace index {}".format(index))

        if isinstance(index, tuple):
            trace_index, sample_index = index
        else:
            trace_index, sample_index = index, None
            
        if isinstance(trace_index, int):
            if trace_index > self.header_handler.number_of_traces:
                raise IndexError("Trace index out of range")
            traces = [trace_index]
        elif isinstance(trace_index, slice):
            start, stop, step = trace_index.indices(self.header_handler.number_of_traces)
            traces = list(range(start, stop, step))
        else:
            try:
                traces = [i if i >= 0 else self.header_handler.number_of_traces + i 
                    for i in index]
            except:
                raise IndexError("Unsupported Trace index {}".format(index))

        for tracenum in traces:
            self.__ith(tracenum)
            data.append(self.__get_trace_data(sample_index))

        return self.organize_trace_data(data)

    def __get_trace_data(self, index=None):
        data = self.__read(self.header_handler.single_trace_byte_length)
        if not index:
            pass
        elif isinstance(index, int):
            if index >= self.header_handler.samples_per_trace:
                data = b''
            else:
                data = data[index: index+self.header_handler.sample_length]
        elif isinstance(index, slice):
            # This eliminates outbound indices
            start, stop, step = index.indices(self.header_handler.samples_per_trace)
            self.__forward_samples(start)
            if step == 1:
                data = data[start*self.header_handler.sample_length
                           :stop*self.header_handler.sample_length]
            else:
                data = [data[i*self.header_handler.sample_length:
                            (i+1)*self.header_handler.sample_length]
                            for i in range(start, stop, step)
                ]
        else:
            try:
                samples = [i if i >= 0 else self.header_handler.samples_per_trace + i 
                            for i in index]
            except TypeError:
                print("Uniterable indexing unapproved")
            for each in samples:
                if each >= self.header_handler.samples_per_trace:
                    raise IndexError("Index out of range")
            if samples:
                data = [data[i*self.header_handler.sample_length:
                    (i+1)*self.header_handler.sample_length]
                    for i in samples
                ]
            else:
                data = b''

        return data

    def set_trace_mask(self, mask):
        ...
    
    def __parse_single_sample(self, b:bytes):
        assert len(b) == self.header_handler.sample_length
        if self.header_handler.sample_coding == 'float':
            return struct.unpack('f', b)[0]
        else:
            assert self.header_handler.sample_coding == 'int'
            ## default is SIGNED INT
            if self.header_handler.sample_length == 1:
                return struct.unpack('b', b)[0]
            elif self.header_handler.sample_length == 2:
                return struct.unpack('h', b)
            else:
                return struct.unpack('i', b)[0]

    def __frombytes(self, b:bytes):
        l = len(b)
        assert l % self.header_handler.sample_length == 0
        nsamples = l // self.header_handler.sample_length
        samples = []
        for i in range(0, nsamples, self.header_handler.sample_length):
            sample = self.__parse_single_sample(b[i:i+self.header_handler.sample_length])
            samples.append(sample)
        return samples
    
    def __fromlist(self, bytelist:list):
        samples = []
        for b in bytelist:
            sample = self.__frombytes(b)
            samples += sample
        return samples

    def organize_trace_data(self, data):
        ext = []
        if isinstance(data, list):
            for d in data:
                if isinstance(d, bytes):
                    ext.append(self.__frombytes(d))
                else:
                    ext.append(self.__fromlist(d))
        elif isinstance(data, bytes):
            ext.append(self.__frombytes(data))
        
        if len(ext) == 1 and isinstance(ext, list):
            ext = ext[0]

        return ext