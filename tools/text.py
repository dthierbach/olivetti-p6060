#!/usr/bin/env python3

import argparse
import os.path

from struct import unpack_from

class AccessExtract:

    bytes = 128 # bytes per sector
    
    def __init__(self, f_in):
        self.f = f_in
    
    def read(self, record):
        self.f.seek(record * self.bytes)
        buf = self.f.read(self.bytes)
        return buf

# for now: scan for 0xc6 0x80
def print_text(access, start):
    record = start // 128
    buf = access.read(record)
    if buf[0] != 0xc6 or buf[1] != 0x80:
        print("No directory entry mark")
        exit(1)
    fname = buf[0x06:0x0c].decode("ascii")
    arg2, = unpack_from(">H", buf, offset=0x02)
    arg3, = unpack_from(">H", buf, offset=0x04)
    arg4, = unpack_from(">B", buf, offset=0x0c)
    ftype = buf[0x0d:0x0e].decode("ascii")
    dcreat = buf[0x2a:0x30].decode("ascii")
    dlastm = buf[0x30:0x36].decode("ascii")
    dxxx   = buf[0x36:0x3c].decode("ascii")
    code   = buf[0x3c:0x44].decode("ascii")
    print(f"{record*128:06x}  {fname} {ftype} {arg2:5} {arg3:5} {arg4} {dcreat:6} {dlastm:6} {dxxx:6} {code}")
    print()
    # TODO header sector
    end = record + max(arg2, arg3)
    record = record + 2
    eof = False
    while not eof and record <= end:
        # print(f"> {record}") 
        buf = access.read(record)
        offset = 0
        while not eof:
            if buf[offset] == 0x00:
                eof = True
            elif buf[offset] == 0xfe:
                print()
            else:
                print(chr(buf[offset]), end='')
            offset = offset + 1
            if eof or offset >= 128:
                record = record + 1
                break
    print
            
parser = argparse.ArgumentParser(description='Catalog P6FSYS')
parser.add_argument('-o', dest='outfile', type=argparse.FileType('w'))
parser.add_argument(dest='start', type=lambda x: int(x,0), help="Start address (hexadecimal with 0x)")
parser.add_argument(dest='infile', type=argparse.FileType('rb'))
args = parser.parse_args()

access = AccessExtract(args.infile)
    
print_text(access, args.start)
