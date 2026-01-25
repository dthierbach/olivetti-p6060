#!/usr/bin/env python3

import argparse
import os.path

from struct import unpack_from

class AccessImd:
    """
    Access IMD image
    """

    def __init__(self, f_in):
        self.f = f_in
    
    def read(self, record):
        return None



class AccessVtoc:
    """
    Access raw image, using vtoc to restrict to one dataset
    """

    bytes = 128 # bytes per sector
    
    def __init__(self, access, name):
        self.access = access
        self.begin = None
        self.end = None
        self.find_dataset(name)
    
    def read(self, record):
        # print(f"read vtoc {record*self.bytes:06x} {record}") ##**
        pos = record + self.begin
        if pos < self.begin or pos > self.end:
            return None
        buf = self.access.read(pos)
        return buf

    def record_cyl_sect(self, cyl, sect):
        return cyl * 26 + sect - 1

    def find_dataset(self, name):
        for sect in range(8,27):
            buf = self.access.read(self.record_cyl_sect(0, sect))
            # print(f"{sect} {buf[0:4]}") ##**
            if buf[0:4] != b'HDR1':
                continue
            vname = buf[5:22].decode("ascii")
            print(f"name='{vname}'")
            vname = vname[0:8].strip()
            if vname != name:
                continue
            ext_beg = buf[28:33].decode("ascii")
            ext_end = buf[34:39].decode("ascii")
            print(f"  {ext_beg}-{ext_end}")
            ext_beg_cyl  = int(ext_beg[0:2])
            ext_beg_sect = int(ext_beg[3:5])
            ext_end_cyl  = int(ext_end[0:2])
            ext_end_sect = int(ext_end[3:5])
            self.begin = self.record_cyl_sect(ext_beg_cyl, ext_beg_sect)
            self.end   = self.record_cyl_sect(ext_end_cyl, ext_end_sect)
            break
        print(f"  {self.begin}-{self.end}")

class AccessFile:

    bytes = 128 # bytes per sector
    
    def __init__(self, f_in):
        self.f = f_in
    
    def read(self, record):
        # print(f"read file {record*self.bytes:06x}") ##**
        self.f.seek(record * self.bytes)
        buf = self.f.read(self.bytes)
        return buf

# for now: scan for 0xc6 0x80
def catalog(access):
    record = -1
    expect = None
    while True:
        record = record + 1
        buf = access.read(record)
        if buf is None or len(buf) == 0:
            if expect:
                print(f"{expect*128:06x} end")
            break
        if buf[0] == 0xc6 and buf[1] == 0x80:
            if expect and record > expect:
                print(f"{expect*128:06x} free")
            if expect and record < expect:
                print(f"{expect*128:06x} clash")
            fname = buf[0x06:0x0c].decode("ascii")
            arg2, = unpack_from(">H", buf, offset=0x02)
            arg3, = unpack_from(">H", buf, offset=0x04)
            arg4, = unpack_from(">B", buf, offset=0x0c)
            ftype = buf[0x0d:0x0e].decode("ascii")
            dcreat = buf[0x2a:0x30].decode("ascii")
            dlastm = buf[0x30:0x36].decode("ascii")
            dxxx   = buf[0x36:0x3c].decode("ascii")
            code   = buf[0x3c:0x44].decode("ascii")
            expect = record + arg2
            print(f"{record*128:06x}  {fname} {ftype} {arg2:5} {arg3:5} {arg4} {dcreat:6} {dlastm:6} {dxxx:6} {code}")
            
parser = argparse.ArgumentParser(description='Catalog P6FSYS')
parser.add_argument(dest='infile', type=argparse.FileType('rb'))
args = parser.parse_args()

access1 = AccessFile(args.infile)
access2 = AccessVtoc(access1, "P6FSYS")
accessx = access2
    
catalog(accessx)
