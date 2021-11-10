import struct
import numpy as np
from numpy.core.fromnumeric import trace
from .TraceHandler import HeaderHandler as inspector_header

# This class can only process SINGLE Inspector file with header
class InspectorFileDataLoader:    
    def __init__(self, fileinput=None, with_header=False, *args, **kargs) -> None:
        self.header_handler = inspector_header()
        if with_header:
            self.header, self.start_offset = self.header_handler.parse_file(fileinput)
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
        self.__prepare_crypto_data()

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

        def trace_data_generator(tracenum):
            self.__ith(tracenum)
            return self.__get_trace_data()

        trace_data_wrapper = trace_data_generator(trace_index=traces)

        for tracenum in traces:
            self.__ith(tracenum)
            data.append(self.__get_trace_data(sample_index))

        reader = TraceReader(self.header_handler, trace_data_wrapper)
        return reader

    def __get_trace_data(self, index=None):
        if not index:
            data = self.__read(self.header_handler.single_trace_byte_length)
        elif isinstance(index, int):
            if index >= self.header_handler.samples_per_trace:
                data = b''
            else:
                self.__forward_samples(index)
                data = self.__read_samples(1)
                self.__rewind_samples(index)
        elif isinstance(index, slice):
            data = []
            # This eliminates outbound indices
            start, stop, step = index.indices(self.header_handler.samples_per_trace)
            self.__forward_samples(start)
            if step == 1:
                data = self.__read_samples(stop - start)
            else:
                while start < stop if step > 0 else start > stop:
                    data.append(self.__read_samples(1))
                    start += step
                    self.__forward_samples(step) # when step < 0 it basically rewinds
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
                data = []
                self.__forward(samples[0])
                data.append(self.__read_samples(1))
                for i in range(1, len(samples)):
                    self.__forward(samples[i] - samples[i-1])
                    data.append(self.__read_samples(1))
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
        
        if len(ext) == 1 and isinstance(exit, list):
            ext = ext[0]

        return ext

class TraceReader:
    def __init__(self, header:inspector_header, trace_data) -> None:
        self.sample_coding = header.sample_coding
        self.sample_length = header.sample_length
        self.trace_data_generator = trace_data

    def __getitem__(self, index):
        data = []
        if not index:
            data = self.__read(self.header_handler.single_trace_byte_length)
        elif isinstance(index, int):
            if index >= self.header_handler.samples_per_trace:
                data = b''
            else:
                self.__forward_samples(index)
                data = self.__read_samples(1)
                self.__rewind_samples(index)
        elif isinstance(index, slice):
            data = []
            # This eliminates outbound indices
            start, stop, step = index.indices(self.header_handler.samples_per_trace)
            self.__forward_samples(start)
            if step == 1:
                data = self.__read_samples(stop - start)
            else:
                while start < stop if step > 0 else start > stop:
                    data.append(self.__read_samples(1))
                    start += step
                    self.__forward_samples(step) # when step < 0 it basically rewinds
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
                data = []
                self.__forward(samples[0])
                data.append(self.__read_samples(1))
                for i in range(1, len(samples)):
                    self.__forward(samples[i] - samples[i-1])
                    data.append(self.__read_samples(1))
            else:
                data = b''
        for trace in self.trace_data_generator:
            ...

    def __parse_single_sample(self, b:bytes):
        assert len(b) == self.sample_length
        if self.sample_coding == 'float':
            return struct.unpack('f', b)[0]
        else:
            assert self.sample_coding == 'int'
            ## default is SIGNED INT
            if self.sample_length == 1:
                return struct.unpack('b', b)[0]
            elif self.sample_length == 2:
                return struct.unpack('h', b)
            else:
                return struct.unpack('i', b)[0]

    def __frombytes(self, b:bytes):
        l = len(b)
        assert l % self.sample_length == 0
        nsamples = l // self.sample_length
        samples = []
        for i in range(0, nsamples, self.sample_length):
            sample = self.__parse_single_sample(b[i:i+self.sample_length])
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
        
        if len(ext) == 1 and isinstance(exit, list):
            ext = ext[0]

        return ext