#!/usr/bin/env python3

# produce radare commands for OS

import sys
from struct import unpack_from

name = '../extract/system/P6SW'

prolog = [0x18, 0x0d, 0x41, 0xd0, 0x00, None, 0x23, 0xdd, 0x50, 0x00, 0xd0, 0x00]

epilog = [0x58, 0xd0, 0xd0, 0x00, 0x41, 0x00, 0x00, None, 0x22, 0x00, 0x28, 0x00]

# damaged segments

# global
segs = {}
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
    # Seg 10
    0x1f82,
    0x205a, 0x205d, 0x22aa,
    # Seg 26 = catalog
    0x03ece, 0x03ed1, 0x03ed4, 0x03ed7, 0x03eda, 0x03edd, 0x03ee0,
    # Seg 2a = list
    0x052ce, # 0x52d1,
    # Seg 4a = file
    0x09e26, 0x09e29, 0x09eea,
    # Seg 55
    0xcbd0, 0xcbd3, 0xcbd6, 0xce36, 0xce39,
    # Seg 5a
    # 0xed43 .. 0xeddf
    0xed43 +  0*3, 0xed43 +  1*3, 0xed43 +  2*3, 0xed43 +  3*3, 0xed43 +  4*3, 
    0xed43 +  5*3, 0xed43 +  6*3, 0xed43 +  7*3, 0xed43 +  8*3, 0xed43 +  9*3, 
    0xed43 + 10*3, 0xed43 + 11*3, 0xed43 + 12*3, 0xed43 + 13*3, 0xed43 + 14*3, 
    0xed43 + 15*3, 0xed43 + 16*3, 0xed43 + 17*3, 0xed43 + 18*3, 0xed43 + 19*3, 
    0xed43 + 20*3, 0xed43 + 22*3, 0xed43 + 23*3, 0xed43 + 24*3,
    0xed43 + 25*3, 0xed43 + 26*3, 
    0xed43 + 30*3, 0xed43 + 32*3, 0xed43 + 34*3, 
    0xed43 + 35*3, 0xed43 + 36*3, 0xed43 + 37*3, 0xed43 + 38*3, 0xed43 + 39*3, 
    0xed43 + 40*3, 0xed43 + 41*3, 0xed43 + 42*3, 0xed43 + 43*3, 0xed43 + 44*3, 
    0xed43 + 45*3, 0xed43 + 46*3, 
    # 0xed85, 0xeddc, 0xeddf,
    # Seg ??
    0x1294e,
    # Seg 60 = vtoc
    0x101cc, 0x101cf, 0x101d2,
    # Seg 61 = environment
    0x10ad7, 0x10ada, 0x10add,
]    

# missing modules:
# 0009 STA STO = s27
# 0019 SEC     = s69
# 0006 DEC COM LIN = ?

funcs = [
    {'extern': 's10_1960', 'begin': 0x01c60, 'end': 0x01d8a},
    {'extern': 's10_1c88', 'begin': 0x01f88, 'end': 0x02052, 'name': 's10_print'},
    {'extern': 's10_1d64', 'begin': 0x02064, 'end': 0x0212e},
    {'extern': 's10_1e58', 'begin': 0x02158, 'end': 0x0228a},
    # CATALOG 0
    {'extern': 's23_0004', 'begin': 0x03984, 'end': 0x03cde, 'name': 's23_catalog'},
    {                      'begin': 0x03cde, 'end': 0x03db2, 'name': 'f03cde_file'},
    {                      'begin': 0x03db2, 'end': 0x03dbc, 'name': 'f03cde_print_line'},
    {'extern': 's4a_0004', 'begin': 0x09d84},
    {'extern': 's4a_00b0', 'begin': 0x09e30},
    {                      'begin': 0x0cb82, 'end': 0x0cb98, 'name': 'f0cb82'},
    {'extern': 's55_03dc', 'begin': 0x0cbdc, 'end': 0x0ce12},
    {                      'begin': 0x0ce12, 'end': 0x0ce22, 'name': 'f0ce12'},
    {'extern': 's55_0640', 'begin': 0x0ce40},
    {'extern': 's5a_0004', 'begin': 0x0e984, 'end': 0x0ec80, 'name': 's5a_command'},
    # s60_lvtoc
    {'extern': 's71_0004', 'begin': 0x12a04},
    {'extern': 's74_0004', 'begin': 0x12f84},
    {'extern': 's7f_0574', 'begin': 0x16374},
    {'extern': 's24_00c8', 'begin': 0x03fc8, 'name': 's24_space'},     # SPACE  1
    {'extern': 's26_0004', 'begin': 0x04784, 'name': 's26_purge'},     # PURGE  2
    {'extern': 's77_0558', 'begin': 0x13d58, 'name': 's77_create'},    # CREATE  3
    {'extern': 's48_0004', 'begin': 0x09704, 'name': 's48_modify'},     # MODIFY  4
    {'extern': 's49_0078', 'begin': 0x09b78, 'name': 's49_truncate'}, # TRUNCATE  5
    {'extern': 's28_0004', 'begin': 0x04984, 'name': 's28_delete'}, # DELETE  6
    {'extern': 's2a_0004', 'begin': 0x04e84, 'end': 0x05286, 'name': 's2a_list'}, # LIST  7
    {'extern': 's29_0004', 'begin': 0x04b84, 'name': 's29_fetch'}, # FETCH  8
    {'extern': 's6a_0004', 'begin': 0x12084, 'name': 's6a_validate'}, # VALIDATE  9
    {'extern': 's22_0004', 'begin': 0x03384, 'name': 's22_resequence'},     # RESEQUENCE  10
    {'extern': 's12_0004', 'begin': 0x02784, 'name': 's12_new'},    # NEW  11
    {'extern': 's55_0004', 'begin': 0x0c804, 'end': 0x0cb82, 'name': 's55_old'},    # OLD  12
    {'extern': 's77_0004', 'begin': 0x13804},    # SAVE  13
    {'extern': 's1f_0004', 'begin': 0x03204},    # REPLACE  14
    {'extern': 's25_0004', 'begin': 0x04284},    # OPTIONS  15
    {'extern': 's24_0004', 'begin': 0x03f04},    # DATE  16
    {'extern': 's24_0240', 'begin': 0x04140},    # STKEYS  17
    {'extern': 's24_02b4', 'begin': 0x041b4},    # LDKEYS  18
    {'extern': 's22_0308', 'begin': 0x03688},    # SHIFT  19
    {'extern': 's25_04e4', 'begin': 0x04764},    # CONFIGURE 20
    # (missing) s69_0004   SECURE 21
    {'extern': 's62_0004', 'begin': 0x10b04},    # PROCEDURE 22
    {'extern': 's79_00d0', 'begin': 0x14f50},    # PREPARE 23
    {'extern': 's79_0004', 'begin': 0x14e84},    # RUN 24
    {'extern': 's72_0004', 'begin': 0x12b84},    # EXE 25
    {'extern': 's1a_0004', 'begin': 0x02984},    # AUTO# 26
    # (missing) s27_0004 START 27
    # (missing) s27_0410 STOP 28
    # (missing) s1b_0004 LINK 29
    {'extern': 's5b_0004', 'begin': 0x0ee04}, # MERGE 30
    # (missing) COMPILE 31
    {'extern': 's57_036c', 'begin': 0x0e3ec}, # TEXT 32
    # (missing) DECOMPILE 33
    {'extern': 's57_0004', 'begin': 0x0e084},    # TRANSCODE 34
    {'extern': 's4c_0004', 'begin': 0x0a184},    # DCHANGE 35
    {'extern': 's5c_0004', 'begin': 0x0f284},    # LBOPEN 36
    {'extern': 's5d_0004', 'begin': 0x0f504},    # LBCLOSE 37
    {'extern': 's5e_0004', 'begin': 0x0f704},    # LBSTORE 38
    {'extern': 's5f_0004', 'begin': 0x0f884},    # LBRESTORE 39
    {'extern': 's60_0004', 'begin': 0x0fa84},    # LVTOC 40
    {'extern': 's61_0004', 'begin': 0x10204, 'end': 0x1071e, 'name': 's61_environment'}, # ENVIRONMENT 41
    {'extern': 's70_0004', 'begin': 0x12904},    # ERASE 42
    {'extern': 's70_0054', 'begin': 0x12954},    # REV 43
    {'extern': 's70_0080', 'begin': 0x12980},    # STI 44
    {'extern': 's6f_0354', 'begin': 0x126d4},    # LDI 45
    {'extern': 's6f_0004', 'begin': 0x12384},    # TES 46
]    

using = [
    # s10_1c60
    {'reg': 'r8',  'begin': 0x01c72, 'end': 0x01d8a},
    # s10_1c88
    {'reg': 'r10', 'begin': 0x01f9a, 'end': 0x01f9a+184},
    {'reg': 'r8',  'begin': 0x02076, 'end': 0x0212e},
    {'reg': 'r10', 'begin': 0x0216a, 'end': 0x0228a},
    # Seg 12 = new
    {'reg': 'r2',  'begin': 0x02786, 'end': 0x0284e},
    # Seg 26 = catalog
    {'reg': 'r7',  'begin': 0x03996, 'end': 0x03dbc},
    # Seg 2a = LIST
    {'reg': 'r3',  'begin': 0x04e92, 'end': 0x05286},
    # Seg 4a = file
    {'reg': 'r3',  'begin': 0x09d96, 'end': 0x09e20},
    {'reg': 'r3',  'begin': 0x09e42, 'end': 0x09ee4},
    # Seg 55
    {'reg': 'r3',  'begin': 0x0c816, 'end': 0x0cb82},
    {'reg': 'r9',  'begin': 0x0cbee, 'end': 0x0ce22},
    {'reg': 'r3',  'begin': 0x0ce52, 'end': 0x0cf24},
    # Seg 5a = command
    {'reg': 'r3',  'begin': 0x0e996, 'end': 0x0ec80},
    {'reg': 'r8',  'begin': 0x0fa96, 'end': 0x10b00},
    {'reg': 'r8',  'begin': 0x10216, 'end': 0x10b00},
    {'reg': 'r8',  'begin': 0x12916, 'end': 0x12946},
    {'reg': 'r8',  'begin': 0x12966, 'end': 0x1297a},
    {'reg': 'r8',  'begin': 0x12992, 'end': 0x129aa},
    {'reg': 'r3',  'begin': 0x12f96, 'end': 0x13780}
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
    newfuncs = []
    oldfuncs = {}
    for f in funcs:
        if 'extern' in f:
            oldfuncs[f['begin']] = f
    print (f"fs relocs")
    for addr in reloc:
        ext_seg, ext_ofs = unpack_from('>BH', fw, addr)
        name = f"s{ext_seg:02x}_{ext_ofs:04x}"
        print (f"Cf 3 bw seg offset @ 0x{addr:x}")
        print (f"f reloc.{addr:05x}.{name} 3 @ 0x{addr:x}")
        seg_begin = segs[ext_seg]['begin']
        seg_end   = segs[ext_seg]['end']
        begin = seg_begin + ext_ofs
        if begin not in oldfuncs:
            print(f"# reloc=0x{addr:05x} seg={segs[ext_seg]}", file=sys.stderr)
            print(f"    {{'extern': '{name}', 'begin': 0x{begin:05x}}},", file=sys.stderr)

        
def analyze_seg(fw, tab_num, addr):
    global segs, seg_maxlen
    seg_num, seg_len = unpack_from('>BxH', fw, addr)
    if seg_num != tab_num:
        print(f"# damaged {tab_num:02x} -> {seg_num:02x}")
        segs[tab_num] = {'begin': addr, 'end': addr}
        return
    # points to the 0xff following the segment
    end = addr + seg_len + 4
    if seg_len > seg_maxlen:
        seg_maxlen = seg_len
    segs[tab_num] = {'begin': addr, 'end': end}
    print(f"CC ==== Segment {seg_num:02x} @ 0x{addr:x}")
    print(f"Cf 4 bbw segment active len @ {addr}")
    print(f"fs segments")
    print(f"f segment.s{seg_num:02x} {seg_len+4} @ 0x{addr:x}")
    # print(f"# analyze {seg_num:02x} {addr:05x} {seg_len} bytes")
    search(fw, addr, end)

def print_using():
    print("fs using")
    for u in using:
        r = u['reg']
        b = u['begin']
        e = u['end']
        print(f"f using.{r}_{b:x} (0x{e:x}-0x{b:x}) @ 0x{b:x}")
    
def print_funcs():
    print("fs functions")
    for f in funcs:
        fx = f.get('extern')
        fn = f.get('name')
        fb = f['begin']
        fe = f.get('end')
        name = fn
        if fn == None:
            fn = fx
        fs = fe
        if fs == None:
            fs = fb
        print(f"f {fn} (0x{fs:x}-0x{fb:x}) @ 0x{fb:x}")
        print(f"af+ 0x{fb:x} {fn}")
        if fe != None:
            print(f"afb+ 0x{fb:x} 0x{fb:x} (0x{fe:x}-0x{fb:x})")

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
    for i in range(0,48):
        print(f"Cs 3 @ 0xec86 + {i}*3")
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
        j = [s for s in sorted(mods[i])]
        k = (i - 0x161) * 0x80
        # print(f"{i:04x} {k:05x} {j}", file=sys.stderr)
        analyze_seg(fw, j[-1], k)
    analyze_reloc(fw)
    print_using()
    print_funcs()
    hardwired()
    # seg_maxlen = 0x1fac
    # print(f"# max seg len 0x{seg_maxlen:x}")
        

with open(name, 'rb') as file:
    fw = file.read()
    analyze(fw)


