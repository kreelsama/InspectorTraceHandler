import re
import os
import struct
from tqdm import tqdm

sourcedir = r"\\loccs_nas\SideChannelData\PowerTrace\PS_trace\E"
sourcefiles = r"E0[0-9][0-9].trs"

destfile = r"\\loccs_nas\SideChannelData\PowerTrace\PS_trace\merged.trs"

chunksize = 32*1024*1024 # 32M

def determine_length(filelist):
    num_of_traces = 0
    for filepath in filelist:
        with open(filepath, 'rb') as f:
            broad_header = f.read(100)
            traces_contained = struct.unpack("I", broad_header[2:6])[0]
            # print(filepath, traces_contained)
            num_of_traces += traces_contained
    return num_of_traces

def get_filelist():
    filelist = []
    for file in os.listdir(sourcedir):
        if not re.match(sourcefiles, file):
            continue
        filepath = os.path.join(sourcedir, file)
        if os.path.isfile(filepath):
            filelist.append(filepath)
    return filelist


def rebuile_header(len:int):
    return b"\x41\x04" + struct.pack("I", len) + b"\x42\x04\x80\xa8\x12\x01\x43\x01\x02\x44\x02\x10\x05\x5f\x00"

def merge():
    filelist = get_filelist()
    number_of_traces = determine_length(filelist)
    print("Total number of traces:", number_of_traces)
    header = rebuile_header(number_of_traces)
    total_size = number_of_traces * 2 * 18e6 + 1040 + 256
    bar = tqdm(total=int(total_size/(1024*1024))+1, unit="MB") # displayed in Megabytes
    bar.update(0)
    done_size = 0
    with open(destfile, 'wb') as dest:
        dest.write(header)
        for filepath in filelist:
            with open(filepath, 'rb') as file:
                broad_header = file.read(100)
                pos = broad_header.find(b'\x5f\x00')
                pos += 2
                file.seek(pos, 0)
                while content := file.read(chunksize):
                    dest.write(content)
                    done_size += len(content)
                    bar.update(int(len(content)/(1024*1024)))
                    # bar.display()
                print("Done with file " + filepath)
    bar.close()
                



if __name__ == '__main__':
    merge()