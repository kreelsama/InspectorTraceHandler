filename = r"/mnt/c/Users/kreel/Desktop/traces/merged.trs"

with open(filename, "r+b") as f:
    f.seek(2)
    f.write(b"\xc1\x08\x00\x00")