#!/usr/bin/env python3

import sys

import argparse

# https://pypi.org/project/ebcdic/
#  https://vtda.org/bits/1_ccmp-utilities/ImageDisk/imd118.zip
# imd118.zip
# IMD.TXT chapter 6

class EOF(Exception):
    pass

def read_bytes(f_in, len):
    buf = f_in.read(len)
    if buf: 
        return int.from_bytes(buf, "little")
    else:
        raise EOF

def dump_data(data, len):
    i = 0
    width = 16
    while i < len:
        print(f"{i:02x}: ", end='')
        for j in range(width):
            print(f" {data[i+j]:02x}", end='')
        print('  ', end='')
        for j in range(width):
            c = chr(data[i+j] & 0x7f)
            if not c.isprintable():
                c = '.'
            print(f"{c}", end='')
        print()
        i += width

def load_comment(f_in):
    print(f"-- {f_in.tell():06x} file comment")
    byte = f_in.read(1)
    while byte != b'\x1a':
        print(byte.decode('ascii'))
        byte = f_in.read(1)

def load_header(f_in):
    print(f"-- {f_in.tell():06x} file header")
    byte = f_in.read(29)
    print(byte)

def load_track(f_in):
    print(f"-- {f_in.tell():06x} track")
    track={}
    track["mode"] = read_bytes(f_in,1)
    track["cyl"] = read_bytes(f_in,1)
    headb = f_in.read(1)[0]
    track["head"] = headb & 1
    if headb & ~1 != 0:
        print(f"head flags set: {headb}")
    headmap_flag = (headb & 0x40) != 0
    cylmap_flag = (headb & 0x80) != 0
    track["num"] = read_bytes(f_in,1)
    track["len"] = 2**(7+read_bytes(f_in,1))
    smap = f_in.read(track["num"])
    i = 1
    for s in smap:
        if s != i:
            print(f"non linear sector map {i}:{s}")
        i += 1
    if headmap_flag:
        headmap = f_in.read(track["num"])
    if cylmap_flag:
        cylmap = f_in.read(track["num"])
    print(f'track={track}')
    return track

def load_data(f_in, f_out, sector, track):
    len = track["len"]
    cyl = track["cyl"]
    head = track["head"]
    print(f"-- {f_in.tell():06x} data cyl={cyl} head={head} sector={sector}")
    mode = read_bytes(f_in, 1)
    print(f"mode={mode}")
    if mode == 0:
        return
    mode -= 1
    if (mode & 1) == 1:
        x = read_bytes(f_in, 1)
        print(f"compressed {x:02x}")
        data = bytes([x for i in range(len)])
    else:
        data = f_in.read(len)
    dump_data(data, len)
    if f_out:
        print(f">> {f_out.tell():06x}")
        f_out.write(data)

def load_all(f_in, f_out):
    load_header(f_in)
    load_comment(f_in)
    t = 0
    try:
        while True:
            track = load_track(f_in)
            for s in range(track["num"]):
                load_data(f_in, f_out, s+1, track)
    except EOF:
        pass
    
# main

parser = argparse.ArgumentParser(description='Decode image disk file')
parser.add_argument('-o', dest='outfile', type=argparse.FileType('wb'))
parser.add_argument(dest='infile', type=argparse.FileType('rb'))
args = parser.parse_args()

print("---- dump")
load_all(args.infile, args.outfile)
print("---- end")

