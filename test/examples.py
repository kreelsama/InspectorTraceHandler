import os, sys
sys.path.append("/home/kreel/")

from TraceHandler import TraceHandler
from tqdm import trange

def merge_file_without_header():
    filename_format = r"/mnt/share/FPGA/FPGA_{:0>4}_aligned.trs"
    handler = TraceHandler(embed_crypto_data=True)
    for idx in trange(10000, desc="processing headers", unit="file"):
        filename = filename_format.format(idx)
        handler.append_file(filename)
    number_of_points = os.path.getsize(filename_format.format(0))
    handler.set_attribute(
        NS=number_of_points,
        SC='int8',
        GT=b"Traces for Attacking FPGA",
        DS=16
    )

    def xor_bytes(s1:bytes, s2:bytes):
        assert len(s1) == len(s2)
        l = len(s1)
        return bytes([s1[i] ^ s2[i] for i in range(l)])

    def data_getter(cnt, i, j):
        with open(r"/mnt/h/FPGA_stream/Attack_FPGA_{:0>4}.bit".format(cnt), 'rb') as fp:
            data = fp.read(1000)
        return xor_bytes(data[0x104:0x114], data[0x11C:0x12C])
    handler.generate_header()
    handler.summary()
    input()
    handler.save2trs(r"/mnt/share/FPGA/merge.trs", crypto_data_getter=data_getter)


def test_header():
    handler = TraceHandler(embed_crypto_data=False)
    handler.set_attribute(
        NS=int(32e6),
        SC='int8',
        GT=b"Traces for Attacking FPGA",
        DS=16
    )
    return handler.generate_header_bytes()

if __name__=='__main__':
    merge_file_without_header()