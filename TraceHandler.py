from tqdm import tqdm

from .HeaderHandler import HeaderHandler

class TraceHandler:
    def __init__(self, with_header=False, embed_crypto_data=False) -> None:
        self.header_handler = HeaderHandler()
        self.filelist = []
        self.buffer = b''
        self.transformer = lambda x: x
        self.with_header = with_header
        self.file_format = 'binary' # or 'npy', if 'npy', then with_header should be False
        self.embed_crypto = embed_crypto_data
        self.file_info = {}
    
    def __write_buffer(self, outfile, chunksize, clear=False):
        while len(self.buffer) >= chunksize or (clear and self.buffer):
            outfile.write(self.buffer[:chunksize])
            self.buffer = self.buffer[chunksize:]
    
    def __parse_header_from_file(self, file):
        with open(file, 'rb') as f:
            broad_header = f.read(2000) # max header length is less than 2000
        header_dict, offset = self.header_handler.parse(broad_header)
        if header_dict:
            return header_dict, offset
        else:
            raise ValueError("Invalid header at {}.".format(offset))

    def __read_one_trace(self, IO):
        crypto_len = self.header_handler['DS']
        sample_size = self.header_handler['SC'] & 0xf
        sample_number = self.header_handler['NS']
        if crypto_len and not self.embed_crypto:
            size = crypto_len + sample_size * sample_number
        else:
            size = sample_size * sample_number
        
        buffer = IO.read(size)
        if buffer:
            assert len(buffer) == size
        return buffer

    def generate_header_bytes(self):
        return self.header_handler.build()
    
    def set_attribute(self, **kwargs):
        self.header_handler.set_header_manually(**kwargs)

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
            try:
                header_dict, offset = self.__parse_header_from_file(filename)
                self.file_info[filename] = [header_dict, offset]
            except ValueError:
                self.file_info[filename] = None
    
    def append_files(self, filenames:iter):
        if isinstance(filenames, str):
            self.append_file(filenames)
        elif isinstance(filenames, iter):
            for file in filenames:
                self.append_file(file)
        else:
            raise NameError

    def transform(self, transformer):
        self.transformer = transformer

    def save2trs(self, output:str, crypto_data_getter=None, chunksize=1024*1024*4):
        '''
        crypto_data_getter(cnt, i, j) return cryptodata that's to 
        be embedded into the final trs file for j-th trace of i-th
        inputted trace file, with cnt-th trace processed in total.
        '''
        if self.embed_crypto:
            assert crypto_data_getter

        if not self.header_handler:
            self.generate_header()
        
        out = open(output, 'wb')
        out.write(self.header_handler.build())
        trace_cnt = 0
        bar = tqdm(total=self.header_handler['NT'], unit="traces")
        for i, file in enumerate(self.filelist):
            bar.set_description("Processing {}".format(file))
            tracefile = open(file, 'rb')
            j = 0
            while True:
                one_trace = self.__read_one_trace(tracefile)
                if not one_trace: break
                bar.update(1)
                crypto_data = b''
                if self.embed_crypto:
                    crypto_data = crypto_data_getter(trace_cnt, i, j)
                self.buffer += crypto_data + self.transformer(one_trace)
                self.__write_buffer(out, chunksize)
            tracefile.close()
        self.__write_buffer(out, chunksize, clear=True)
        bar.close()
        out.close()

    def generate_header(self):
        if self.with_header:
            for filename in self.filelist:
                header, _ = self.file_info[filename][0]
                self.header_handler.update(header)
            self.summary()
        else:
            for filename in self.filelist:
                trace_number = self.get_file_trace_number(filename)
                self.header_handler.increment_number_of_traces(trace_number)
    
    def toNumpy(self):
        raise NotImplementedError
    
    def summary(self):
        if self.header_handler:
            print("Merging {} traces with {} points each".format(
                self.header_handler['NT'],
                self.header_handler['NS']
            ), end='')
        else:
            raise LookupError("No header provided")
        if self.header_handler['DS']:
            print(" and {} bytes of crypto data".format(self.header_handler['DS']), end='')
        print()
    
    def get_file_trace_number(self, filename:str):
        # (crypto_len + sample_size*sample_number) * trace_number + header_length == file_size
        import os
        if self.file_info[filename]:
            header, _ = self.file_info[filename]
            return header['NT'] # in bytes
        else: # headerless
            file_size = os.path.getsize(filename)
            if not self.header_handler:
                raise LookupError("No header provided")
            crypto_len = 0
            if self.header_handler['DS'] and not self.embed_crypto:
                crypto_len = self.header_handler['DS']
            sample_size = self.header_handler['SC'] & 0xf
            assert sample_size in [1,2,4]
            sample_number = self.header_handler['NS']
            if file_size % (crypto_len + sample_size*sample_number):
                print("file {} unaligned data".format(filename))
            return file_size // (crypto_len + sample_size*sample_number)