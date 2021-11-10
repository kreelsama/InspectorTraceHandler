## Python Script for Processing Inspector Traces

Inconveniences occur when we want to manipulate inspector traces such as merging, data transforming etc.

This script intends to ease the following procedures:
- Transfer and merge raw data (trace) file(s) to a single Inpsector Tracefile
- Merge tracefiles (with or without header) to a single Tracefile with header
- Embed crypto data into tracefiles
- Convert tracefiles to numpy arrays
- Indexing Tracefile as arrays while avoiding loading into system memory

The Repo is partially usable at this time, so issues are open for undetected bugs and unimplemented functionalities.

### Tested Examples

#### Import this lib

Put this repo in some location , say `\this\location\InspectorTraceHandler`

```python
import sys
sys.path.append("\this\location\InspectorTraceHandler")

# Import here
from InspectorTraceHandler import TraceHandler, HeaderHandler, InspectorFileDataLoader
```

#### Merging Headerless Tracefiles

Supposing you have collected numerous waveform files directly from your oscilloscope, and waveform files are without proper header and each file contains different number of traces with identical encoding and data length.  Then it is possible to merge them with the following way:

**Add file names**

```python
from InspectorTraceHandler import TraceHandler
# your file list
filenames = ['1.bin', '2.bin', ...]

handler = TraceHandler(with_header=False)

# reconmended
for file in filenames:
    handler.append_file(file)
    
# or if your filenames is iterable:
hander.append_files(filenames)
```

**Set header manually**

This is quite necessary because at least three attributes (number of traces, trace encoding, samples per trace) are needed for building a valid header.

Number of traces will be calculated and incremented automatically thus no need to set. Trace encoding (SC) and samples per trace (NS) are required to set when dealing with headerless tracefiles.

```python
handler.set_attribute(
    NS=number_of_points,
    SC='int8',
    GT=b"Traces for Attacking FPGA",
)

handler.generate_header()
```

You can set any attribute by  `handler.set_attribute(name1=attr1, name2=attr2, ...)` where names are from Inspector Header Set Coding Table (available from attached `Inspector.pdf`).

*Note*: Attributes have to be set properly before trace merging, or the merging will not proceed. It is also possible to change some attributes when processing tracefiles with header.

Then call `handler.generate_header()` to generate final header bytes. This procedure scans the entire file list and determine number of traces. This procedure will be called explicitly before merging even if not being called implicitly.

**Begin merging**

```python
handler.save2trs(filename, chunksize)
```

This begins merging. `filename` is the final filename you want to save and chunksize is the number of bytes per writing to the filesystem (default to 4M).

**Embed crypto data into final tracefile**

Use `handler = TraceHandler(with_header=<True/False>, embed_crypto=True)` to create object and set crypto data length in the header by `DS=<length>` . When calling `save2trs`  a new function parameter `crypto_data_getter` should be giving, accepting 3 parameters `(cnt, i, j)` and returning corresponding crypto data bytes with length=`<length>`.  traces under processing is the `cnt`-th trace accumulated and is  `j`-th trace from `i`-th file. 

*Note:* you can't embed crypto data if there already exists crypto data defined in the header.

**Merging files with header** 

Use `handler = TraceHandler(with_header=True)` and if there is no crypto data defined you can set `embed_crypto=True`  and use `set_attribute` to define crypto data length only (no need to set attributes that's already in the header). Then call `save2trs` to merge.

#### Indexing a single Inspector like an array

This is created for saving system memory. This utility currently suits for reading a single Inspector tracefile with header.

```python
# This will be a bit slower because crypto data is loaded during initialization
dataloader = InspectorFileDataLoader(filename, with_header=True)

# trace number 5
dataloader[5]

# trace number 10 to 230
dataloader[10:230]

# all traces
dataloader[:]

# sample 100 from trace number 10 to 50
dataloader[10:50, 100]

# sample 3000:4000 from all traces
dataloader[:, 3000:4000]

# sample 1,100,1000 from trace 5,10,1000
dataloader[[5,10,1000], [1,100,1000]]

# crypro data number 10
dataloader.crypto_data[10]
```

Indexing is basically like numpy array and matlab matrix.

**Note**: It is not recommended to index all traces first and then index selected traces subsequently like  `dataloader[:][100:200]` to get trace from 100 to 200. This basically loads all traces into your memory and then performing indexing afterwards.

**Performance Note:** Every indexing is directly performed on your file system, so a good hard drive is preferred, or the indexing could be slow.

**Trace to numpy**
if your memory is enough you can:
 ```python
 import numpy as np
 
 dataloader = InspectorFileDataLoader(with_header=True)
 trace_data = np.asarray(dataloader[:])
 crypto_data = np.asarray(dataloader.crypto_data[:])
 np.save("tracedata.npy",  trace_data )
 np.save("cryptodata.npy", crypto_data)
 ```

