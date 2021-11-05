import numpy as np
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
            self.index = np.arange(self.header_handler.number_of_traces)
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
        return self.support_data[self.index]
    
    def __del__(self):
        if not self.io.closed:
            self.io.close()
        
    def __getitem__(self, index):
        if isinstance(index, int):
            # eg: [101]
            self.__ith(self.index[index])
            return self.__get_trace_data()
        else:
            ...
    
    def __get_trace_data(self, index=None):
        if not index:
            data = self.__read(self.header_handler.single_trace_byte_length)
        elif isinstance(index, int):
            self.__forward(index)
            data = self.__read(self.header_handler.sample_length)
            self.__rewind(index)
        elif isinstance(index, slice):
            data = []
            indice = index.start
            self.__forward(indice)
            while indice < index.stop:
                ...
        return data

    def set_trace_mask(self, mask):
        ...
    
    def shuffle(self):
        np.random.shuffle(self.index)
        
    def organize_trace_data(self, data):
        ...