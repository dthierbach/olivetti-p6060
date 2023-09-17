#!/usr/bin/env python3

import argparse
import os.path


class AccessRaw:

    bytes = 128 # bytes per sector
    sectors = 26 # sectors per cylinder, start at 1
    
    def __init__(self, f_in):
        self.f = f_in
    
    def read(self, cyl, sect):
        self.f.seek((cyl * 26 + sect - 1) * self.bytes)
        buf = self.f.read(self.bytes)
        return buf

def format_date(x):
    if x.strip():
        return f"{x[4:6]}.{x[2:4]}.19{x[0:2]}"
    else:
        return None

def save_file(access, outdir, name, ext_beg, ext_end):
    out = open(outdir + name, "wb")
    ext_beg_cyl  = int(ext_beg[0:2])
    ext_beg_sect = int(ext_beg[3:5])
    ext_end_cyl  = int(ext_end[0:2])
    ext_end_sect = int(ext_end[3:5])
    cyl = ext_beg_cyl
    sect = ext_beg_sect
    while True:
        # print(f"cyl={cyl} sect={sect}")
        buf = access.read(cyl, sect)
        out.write(buf)
        if cyl == ext_end_cyl and sect == ext_end_sect:
            break
        sect = sect + 1
        if sect > access.sectors:
            sect = 1
            cyl = cyl + 1
    out.close()

    
def load_header(access, outdir, sect):
    buf = access.read(0, sect)
    if buf[0:4] != b'HDR1':
        return
    name = buf[5:22].decode("ascii")
    # print(f"name='{name}'")
    # only first 8?
    name = name[0:8].strip()
    print(f"name='{name}'")
    ext_beg = buf[28:33].decode("ascii")
    ext_end = buf[34:39].decode("ascii")
    date_creat = format_date(buf[47:53].decode("ascii"))
    date_expir = format_date(buf[67:72].decode("ascii"))
    print(f"  {ext_beg}-{ext_end} create={date_creat} expire={date_expir}")
    if outdir:
        save_file(access, outdir, name, ext_beg, ext_end)

def load_vtoc(access, outdir):
    buf = access.read(0, 7)
    if buf[0:4] != b'VOL1':
        print("No VOL1 header")
        return
    label = buf[4:10].decode("ascii")
    print(f"volume label='{label}'")
    for s in range(8,27):
        load_header(access, outdir, s)


parser = argparse.ArgumentParser(description='Decode image disk file')
parser.add_argument('-o', dest='outdir')
parser.add_argument(dest='infile', type=argparse.FileType('rb'))
args = parser.parse_args()

access = AccessRaw(args.infile)
outdir = args.outdir
if outdir:
    if not os.path.isdir(outdir):
        print(f"{outdir} is not a directory")
        exit()
    if not outdir.endswith("/"):
        outdir = outdir + "/"
    
load_vtoc(access, args.outdir)
