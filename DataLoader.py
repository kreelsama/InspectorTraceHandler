import struct
import numpy as np
from .TraceHandler import HeaderHandler as inspector_header

# This class can only process SINGLE Inspector file with header
class InspectorFileDataLoader:    
    def __init__(self, fileinput=None, with_header=False, *args, **kwargs) -> None:
        self.header_handler = inspector_header()
        self.data_indicator = ''
        if with_header:
            self.header, self.start_offset = self.header_handler.parse_file(fileinput)
            self.header_handler.update(self.header)
            self.io = open(fileinput, 'rb')
            self.support_data = np.zeros(shape=(
                self.header_handler.number_of_traces, self.header_handler.crypto_length
                ), dtype=np.dtype('uint8'))
            self.__zero_offset()
            self.prepare(*args, **kwargs)

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
        self.__zero_offset()
        self.io.seek(i * self.header_handler.trace_interval, 1)
        # self.cur = i

    def __read(self, nbytes=None):
        r = self.io.read(nbytes)
        if nbytes:
            self.__rewind(nbytes)
        else:
            self.__zero_offset()
        return r

    def __forward_samples(self, nsamples=0):
        return self.__forward(nsamples * self.header_handler.sample_length)
    
    def __rewind_samples(self, nsamples=0):
        return self.__rewind(nsamples * self.header_handler.sample_length)

    def __read_samples(self, nsamples=0):
        return self.__read(nsamples * self.header_handler.sample_length)

    def prepare(self, cryptolen=0):
        self.__prepare_crypto_data()
        if self.header_handler.sample_coding == 'float':
            self.indicator = 'f'
        else:
            assert self.header_handler.sample_coding == 'int'
            ## default is SIGNED INT
            if self.header_handler.sample_length == 1:
                self.indicator = 'b'
            elif self.header_handler.sample_length == 2:
                self.indicator = 'h'
            else:
                self.indicator = 'i'
        

    def __prepare_crypto_data(self):
        self.__zero_offset()
        if not self.header_handler.crypto_length:
            return None
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
            if trace_index < 0:
                trace_index = self.header_handler.number_of_traces + trace_index
            if trace_index >= self.header_handler.number_of_traces or trace_index < 0:
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

    def __get_trace_data(self, index=None)->bytes:
        data = b''
        if index is None:
            data = self.__read(self.header_handler.single_trace_byte_length)
        elif isinstance(index, int):
            if index < 0:
                index = self.header_handler.samples_per_trace + index
            if index >= self.header_handler.samples_per_trace or index < 0:
                pass
            else:
                self.__forward_samples(index)
                data = self.__read_samples(1)
        elif isinstance(index, slice):
            # This eliminates outbound indices
            start, stop, step = index.indices(self.header_handler.samples_per_trace)
            self.__forward_samples(start)
            if step == 1:
                data = self.__read_samples(stop - start)
            else:
                while start < stop if step > 0 else start > stop:
                    data += self.__read_samples(1)
                    start += step
                    self.__forward_samples(step) # when step < 0 it basically rewinds
        else:
            try:
                samples = [i if i >= 0 else self.header_handler.samples_per_trace + i 
                            for i in index]
            except TypeError:
                print("Uniterable indexing unapproved")
            for each in samples:
                if each >= self.header_handler.samples_per_trace or each < 0:
                    raise IndexError("Index out of range")
            if samples:
                self.__forward_samples(samples[0])
                data += self.__read_samples(1)
                for i in range(1, len(samples)):
                    self.__forward_samples(samples[i] - samples[i-1])
                    data += self.__read_samples(1)
            else:
                data = b''

        return data

    def set_trace_mask(self, mask):
        ...
    
    def __frombytes(self, b:bytes):
        assert len(b) % self.header_handler.sample_length == 0
        l = len(b) // self.header_handler.sample_length
        return struct.unpack(self.indicator*l, b)

    def organize_trace_data(self, data):
        ext = []
        if isinstance(data, list):
            for d in data:
                ext.append(self.__frombytes(d))
        elif isinstance(data, bytes):
            ext.append(self.__frombytes(data))
        
        if len(ext) == 1 and isinstance(ext, list):
            ext = ext[0]

        return ext