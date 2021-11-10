import sys
sys.path.append("/home/kreel/")

from TraceHandler import InspectorFileDataLoader

path = '/mnt/share/FPGA/merge.trs'

data = InspectorFileDataLoader(path, with_header=True)