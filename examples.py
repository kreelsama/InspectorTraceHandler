import os
from TraceHandler import TraceHandler

def merge_file_without_header():
    filename_format = "H:\\FPGA_trace\\raw\\FPGA_{:0>4}.trs"
    handler = TraceHandler(embed_crypto_data=True)
    for idx in range(10000):
        filename = filename_format.format(idx)
        handler.append_file(filename)
    number_of_points = os.path.getsize(filename_format.format(0))
    handler.set_attribute(
        NS=number_of_points,
        SC='int4',
        GT=b"Traces for Attacking FPGA"
    )
    def data_getter(cnt, i, j):
        ...

    handler.save2trs("\\\\loccs_nas\\SideChannelData\\PowerTrace\\FPGA\FPGA_1.trs", crypto_data_getter=data_getter)
