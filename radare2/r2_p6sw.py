#!/usr/bin/env python3

# produce radare commands for OS

import sys
from struct import unpack_from

name = '../extract/system/P6SW'

prolog = [0x18, 0x0d, 0x41, 0xd0, 0x00, None, 0x23, 0xdd, 0x50, 0x00, 0xd0, 0x00]

epilog = [0x58, 0xd0, 0xd0, 0x00, 0x41, 0x00, 0x00, None, 0x22, 0x00, 0x28, 0x00]

# global
seg_maxlen = 0

# using
# f using.r10_1f9a 184 @ 0x1f9a
# f using.r7_3996 (0x3dbc-0x3996)@ 0x3996
# f using.r8_fa96 (0x10b00-0xfa96) @ 0xfa96
# s
# s61 enviroment
# f using.r8_10216 (0x10b00-0x10216) @ 0x10216
# s?
# f using.r3_12f96 (0x13780-0x12f96) @ 0x12f96

# reloc tables

# prefix:
# lxxxx_loop    label
# dxxxx_len     data
# vxxxx_buf     local variable


reloc = [
    # Seg 26 = catalog
    0x03ece, 0x03ed1, 0x03ed4, 0x03ed7, 0x03eda, 0x03edd, 0x03ee0, 0x03ee3,
    # Seg ??
    0x1294e,
    # Seg 60 = btoc
    0x101cc, 0x101cf, 0x101d2
]    

funcs = [
    {'seg': 0x74, 'ofs': 0x0004},
    {'seg': 0x74, 'ofs': 0x0004},
    {'seg': 0x55, 'ofs': 0x03dc},
    {'seg': 0x10, 'ofs': 0x1960},
    {'seg': 0x10, 'ofs': 0x1c88, 'name': 's10_print'},
    {'seg': 0x4a, 'ofs': 0x0004},
    {'seg': 0x4a, 'ofs': 0x00b0}
]    



using = [
    {'reg': 'r7', 'begin': 0x01f9a, 'end': 0x01f9a+184},
    # Seg 26 = catalog
    {'reg': 'r7', 'begin': 0x03996, 'end': 0x03dbc},
    {'reg': 'r8', 'begin': 0x0fa96, 'end': 0x10b00},
    {'reg': 'r8', 'begin': 0x10216, 'end': 0x10b00},
    {'reg': 'r8', 'begin': 0x12916, 'end': 0x12946},
    {'reg': 'r8', 'begin': 0x12966, 'end': 0x1297a},
    {'reg': 'r8', 'begin': 0x12992, 'end': 0x129aa},
    {'reg': 'r3', 'begin': 0x12f96, 'end': 0x13780}
]    

def search(fw, addr, end):
    i = addr;
    pos = 0;
    offset = None
    while i <= end:
        if prolog[pos] == None:
            offset = fw[i]
            pos += 1
        elif fw[i] == prolog[pos]:
            pos += 1
            if pos >= len(prolog):
                j = i-pos+1
                print(f"CC prolog {offset} @ 0x{j:x}")
                pos = 0
                offset = None
        else:
            pos = 0
            offset = None
        i += 1
    
def analyze_reloc(fw):
    print (f"fs relocs")
    for addr in reloc:
        name = f"s{fw[addr]:02x}_{fw[addr+1]:02x}{fw[addr+2]:02x}"
        print (f"Cf 3 bw seg offset @ 0x{addr:x}")
        print (f"f reloc.{name} 3 @ 0x{addr:x}")

        
def analyze_seg(fw, addr):
    global seg_maxlen
    seg, seg_len = unpack_from('>BxH', fw, addr)
    # points to the 0xff following the segment
    end = addr + seg_len + 4
    if seg_len > seg_maxlen:
        seg_maxlen = seg_len
    print(f"CC ==== Segment {seg:02x} @ 0x{addr:x}")
    print(f"Cf 4 bbw segment active len @ {addr}")
    print(f"fs segments")
    print(f"f segment.s{seg:02x} {seg_len+4} @ 0x{addr:x}")
    # print(f"# analyze {seg:02x} {addr:05x} {seg_len} bytes")
    # print(f"# {end:05x}")
    search(fw, addr, end)

def print_using():
    print("fs using")
    for u in using:
        r = u['reg']
        b = u['begin']
        e = u['end']
        print(f"f using.{r}_{b:x} (0x{e:x}-0x{b:x}) @ 0x{b:x}")
    
def hardwired():
    #print("fs using")
    #print("f using.r10_1f9a 184 @ 0x1f9a")
    #print("f using.r7_3996 (0x3dbc-0x3996)@ 0x3996")
    ## print("Cd 1 (0x3f00-0x3dbc) @ 0x3dbc")
    #print("f using.r8_fa96 (0x10b00-0xfa96) @ 0xfa96")
    #print("f using.r8_12916 (0x12946-0x12916) @ 0x12916")
    ## print("Cd 1 (0x12954-0x12946) @ 0x12946")
    #print("f using.r8_12966 (0x1297a-0x12966) @ 0x12966")
    ## print("Cd 1 (0x12980-0x1297a) @ 0x1297a")
    #print("f using.r8_12992 (0x129aa-0x12992) @ 0x12992")
    ## print("# Cd 1 (0x12a00-0x129aa) @ 0x129aa")
    #print("f using.r8_10216 (0x10b00-0x10216) @ 0x10216")
    #print("f using.r3_12f96 (0x13780-0x12f96) @ 0x12f96")
    print("s 0x3980")

def analyze(fw):
    global seg_maxlen
    print(f"Cd 1 3*256 @ 0")
    mod = 0x10
    mods = {}
    while True:
        if mod > 0xfa:
            break
        i, = unpack_from('>H', fw, mod*2)
        # print(f"{mod:02x} {i:04x}")
        if not i in mods:
            mods[i] = []
        mods[i].append(mod)
        mod += 1
    # don't really need to correct it, the last segment is correct
    # others are not used
    seg_maxlen = 0
    for i in sorted(mods):
        j = [f"{k:02x}" for k in sorted(mods[i])]
        k = (i - 0x161) * 0x80
        # print(f"{i:04x} {k:05x} {j}")
        analyze_seg(fw, k)
    analyze_reloc(fw)
    print_using()
    hardwired()
    # seg_maxlen = 0x1fac
    # print(f"# max seg len 0x{seg_maxlen:x}")
        

with open(name, 'rb') as file:
    fw = file.read()
    analyze(fw)


