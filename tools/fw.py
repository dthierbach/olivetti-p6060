#!/usr/bin/env python3

import sys

import argparse
import re
import os.path

parser = argparse.ArgumentParser(description='Decode image disk file')
parser.add_argument(dest='infile', type=argparse.FileType('rb'))
parser.add_argument('-o', '--overlay', action='store_true')
parser.add_argument('-d', '--disasm', type=argparse.FileType('r'))
# '-r', 'replace'
args = parser.parse_args()

class EOF(Exception):
    pass

opcode={}

opcode[0x82]=['y', 'AMIM',  'M', 'A', '[{argx}--] := {argy}']
opcode[0x83]=['F', 'TADI',  'A', '',  'DI := {argx}']
opcode[0x85]=['F', 'ICA',   'A', '',  '{argx}++']
opcode[0x86]=['y', 'ADD',   'A', 'B', '{argx}+{argy}+DI0']
opcode[0x87]=['y', 'ORB',   'A', 'B', '{argy} := {argx} or {argy}']
opcode[0x88]=['y', 'AMIP',  'M', 'A', '[{argx}++] := {argy}']
opcode[0x89]=['y', 'BMI',   'M', 'A', '[{argx}] := {argy}']
opcode[0x8A]=['y', 'BMIM',  'M', 'A', '[{argx}--] := {argy}']
opcode[0x8B]=['F', 'ROTA',  'A', '',  '{argx}.M <-> {argx}.P']
opcode[0x8C]=['y', 'BMIP',  'M', 'A', '[{argx}++] := {argy}']
opcode[0x8D]=['8', 'EMI',   'M', '',  '[{argx}] <- data.B']
opcode[0x8E]=['F', 'VRA',   'A', '',  '{argx}==0']
opcode[0x90]=['0', 'MEI',   'M', '',  'data.B <- [{argx}]']
opcode[0x91]=['y', 'MAI',   'M', 'A', '{argy} := [{argx}]']
opcode[0x92]=['y', 'MAIM',  'M', 'A', '{argy} := [{argx}--]']
opcode[0x93]=['F', 'TBDI',  'B', '',  'DI := {argx}']
opcode[0x94]=['0', 'MEIP',  'M', '',  'data.B <- [{argx}++]']
opcode[0x95]=['F', 'ICB',   'B', '',  '{argx}++']
opcode[0x96]=['y', 'ADDA',  'A', 'B', '{argx} := {argx}+{argy}+DI0']
opcode[0x97]=['y', 'AND',   'A', 'B', '{argx} and {argy}']
opcode[0x98]=['y', 'MAIP',  'M', 'A', '{argy} := [{argx}++]']
opcode[0x99]=['y', 'MBI',   'M', 'B', '{argy} := [{argx}]']
opcode[0x9A]=['y', 'MBIM',  'M', 'B', '{argy} := [{argx}--]']
opcode[0x9B]=['F', 'ROTB',  'B', '',  '{argx}.M <-> {argx}.P']
opcode[0x9C]=['y', 'MBIP',  'M', 'B', '{argy} := [{argx}++]']
opcode[0x9D]=['0', 'MEIM',  'M', '',  'data.B <- [{argx}--]']
opcode[0x9E]=['F', 'VRB',   'B', '',  '{argx}==0']
opcode[0xA1]=['8', 'EMIM',  'M', '',  '[{argx}--] <- data.B']
opcode[0xA2]=['8', 'EMIP',  'M', '',  '[{argx}++] <- data.B']
opcode[0xA3]=['F', 'SDIA',  'A', '',  '{argx} <-> DI']
opcode[0xA5]=['F', 'ICL',   'L', '',  '{argx}++']
opcode[0xA6]=['y', 'ADDB',  'A', 'B', '{argy} := {argx}+{argy}+DI0']
opcode[0xA7]=['y', 'ANDA',  'A', 'B', '{argx} := {argx} and {argy}']
opcode[0xA8]=['y', 'AMI',   'M', 'A', '[{argx}] := {argy}']
opcode[0xA9]=['8', 'EDB',   'B', '',  'data.B -> {argx}']
opcode[0xAA]=['0', 'ENTL',  'L', '',  'name -> {argx}.A, type->{argx}.B']
opcode[0xAB]=['F', 'AZAM',  'A', '',  '{argx}.M := 0']
opcode[0xAD]=['F', 'EDC',   'L', '',  '{argx}.MMM--, ECOF if zero']
opcode[0xAE]=['F', 'ICA',   'A', '',  '{argx}--']
opcode[0xB1]=['4', 'ESE',   'M', '',  'sel.B <- [{argx}]']
opcode[0xB2]=['F', 'ETIB',  'B', '',  'type.B -> {argx}']
opcode[0xB3]=['F', 'SDIB',  'B', '',  '{argx} <-> DI']
opcode[0xB4]=['2', 'ECO',   'M', '',  'cmd.B <- [{argx}]']
opcode[0xB6]=['y', 'SOT',   'A', 'B', '{argx}-{argy}+DI0']
opcode[0xB7]=['y', 'ANDB',  'A', 'B', '{argy} := {argx} and {argy}']
opcode[0xB8]=['8', 'EDA',   'A', '',  'data.B -> {argx}']
opcode[0xB9]=['0', 'ENUA',  'A', '',  'name -> {argx}']
opcode[0xBA]=['y', 'SAB',   'A', 'B', '{argx} <-> {argy} ']
opcode[0xBB]=['F', 'AZAP',  'A', '',  '{argx}.P := 0']
opcode[0xBC]=['y', 'SLL',   'L', 'L', '{argx} <-> {argy}']
opcode[0xBD]=['0', 'COMx',  'C', '',  '  {argx}']
opcode[0xBE]=['F', 'ICB',   'B', '',  '{argx}--']
opcode[0xC3]=['0', 'SHDA',  'A', 'C', '{argx} >>']
opcode[0xC3]=['1', 'SLDA',  'A', 'C', '{argx} >> DI0']
opcode[0xC4]=['0', 'SHSA',  'A', 'C', '{argx} <<']
opcode[0xC4]=['1', 'SLSA',  'A', 'C', '{argx} << DI0']
opcode[0xC5]=['F', 'TDIA',  'A', '',  '{argx} := DI']
opcode[0xC6]=['y', 'SOTA',  'A', 'B', '{argx} := {argx}-{argy}+DI0']
opcode[0xC7]=['y', 'ORE',   'A', 'B', '{argx} xor {argy}']
opcode[0xC8]=['x', 'REDI',  'D', 'D', 'reset DI {argd}']
opcode[0xC9]=['x', 'SEDI',  'D', 'D', 'set DI {argd}']
opcode[0xCB]=['F', 'AZBM',  'B', '',  '{argx}.M := 0']
opcode[0xCA]=['0', 'TCCA',  'A', '',  '{argx} <- con']
opcode[0xD1]=['y', 'MLI',   'M', 'L', '{argy} := [{argx}]']
opcode[0xD3]=['0', 'SHDB',  'B', '',  '{argx} >>']
opcode[0xD3]=['1', 'SLDB',  'B', '',  '{argx} >> DI0']
opcode[0xD4]=['0', 'SHSB',  'B', '',  '{argx} <<']
opcode[0xD4]=['1', 'SLSA',  'B', '',  '{argx} << DI0']
opcode[0xD5]=['F', 'TDIB',  'B', '',  '{argx} := DI']
opcode[0xD6]=['y', 'SOTB',  'A', 'B', '{argy} := {argx}-{argy}+DI0']
opcode[0xD7]=['y', 'OREA',  'A', 'B', '{argx} := {argx} xor {argy}']
opcode[0xD8]=['y', 'TAB',   'A', 'B', '{argy} := {argx}']
opcode[0xD9]=['y', 'TABP',  'A', 'B', '{argy}.P := {argx}.P']
opcode[0xDA]=['1', 'TDMA',  'A', '',  '{argx} <- con.M']
opcode[0xDB]=['F', 'AZBP',  'B', '',  '{argx}.P := 0']
opcode[0xDD]=['y', 'MLIM',  'M', 'L', '{argy} := [{argx}--]']
opcode[0xDE]=['y', 'MLIP',  'M', 'L', '{argy} := [{argx}++]']
opcode[0xE0]=['8', 'ESI',   'M', '',  '[{argx}] <- data/type']
opcode[0xE1]=['y', 'LMI',   'M', 'L', '[{argx}] := {argy}']
opcode[0xE2]=['y', 'LPMIP', 'M', 'L', '[{argx}++] := ++{argy}']
opcode[0xE5]=['F', 'ICL',   'L', '',  '{argx}--']
opcode[0xE6]=['y', 'OR',    'A', 'B', '{argx} or {argy}']
opcode[0xE7]=['y', 'OREB',  'A', 'B', '{argy} := {argx} xor {argy}']
opcode[0xE8]=['y', 'TABM',  'A', 'B', '{argy}.M := {argx}.M']
opcode[0xE9]=['y', 'TBA',   'A', 'B', '{argx} := {argy}']
opcode[0xEA]=['2', 'TDPA',  'A', '',  '{argx} <- con.P']
opcode[0xEB]=['8', 'ESIP',  'M', '',  '[{argx}++] <- data/type']
opcode[0xEC]=['8', 'ESIM',  'M', '',  '[{argx}--] <- data/type']
opcode[0xED]=['y', 'LMIM',  'M', 'L', '[{argx}--] := {argy}']
opcode[0xEE]=['y', 'LMIP',  'M', 'L', '[{argx}++] := {argy}']
opcode[0xF1]=['0', 'SEI',   'M', '',  'data.W <- [{argx}]']
opcode[0xF5]=['F', 'VRL',   'L', '',  '{argx}==0']
opcode[0xF6]=['y', 'ORA',   'A', 'B', '{argx} := {argx} or {argy}']
opcode[0xF7]=['0', 'SEIM',  'M', '',  'data.W <- [{argx}--]']
opcode[0xF7]=['0', 'SEIP',  'M', '',  'data.W <- [{argx}++]']
opcode[0xF8]=['y', 'TBAP',  'A', 'B', '{argx}.P := {argy}.P']
opcode[0xF9]=['y', 'TBAM',  'A', 'B', '{argx}.M := {argy}.M']
opcode[0xFA]=['y', 'TABC',  'A', 'B', ' con <- {argx}, {argy}']
opcode[0xFC]=['0', 'DAE',   'L', '',  'data.W <- {argx}']
opcode[0xFC]=['2', 'CAE',   'L', '',  'cmd.W <- {argx}']

periph={}

# physical names don't apply to COM, fix...
periph[0] = "Internal"
periph[1] = "Free"
periph[2] = "Serial 1 Tx"
periph[3] = "Serial 1 Rx"
periph[4] = "Serial 2 Tx"
periph[5] = "Serial 2 Rx"
periph[6] = "Serial 3 Tx"
periph[7] = "Serial 3 Rx"
periph[8] = "Serial 4 Tx"
periph[9] = "Serial 4 Rx"
periph[10] = "Harddisk"
periph[11] = "Free"
periph[12] = "Floppy"
periph[13] = "IPSO 1"
periph[14] = "IPSO 2"
periph[15] = "Video"


# jumps are not marked by bit 15 = 0 ...

# 2.0
# 00000000  44 30 00 40 30 31 30 32  0102  30 sector = 0xcC00 words  0040-1000
#           44 08 10 00 30 32 32 34  0224  08 sector = 0x0200 words  1000-1200
# 00000010  44 80 a0 00 30 33 30 36  0306  80 sector = 0x2000 words  a000-c000
#           20 10 7c 00 37 34 30 31  7401  10 sector = 0x0400 words
# 00000020  46 01 10 00 00 00 00 00                                  1000

org={}
org[0] = 0
org[128 * 1] = 0x0040
org[128 * (1 + 0x30)] = 0x1000
org[128 * (1 + 0x30 + 0x08)] = 0xa000
org[128 * (1 + 0x30 + 0x08 + 0x80)] = 0x7c00

    
ovl_addr={}
ovl_len={}
ovl_reloc={}
ovl_count=0

relocs={}

secsize = 0x80

def dump_header(f_in):
    global ovl_count
    buf = f_in.read(0x80)
    pos = 0
    n = 0
    while True:
        ovl_addr[n] = (buf[pos] << 8 | buf[pos+1]) * secsize
        if ovl_addr[n] == 0:
            break
        ovl_len[n] = buf[pos+2] * secsize
        ovl_reloc[n] = ovl_addr[n] + (buf[pos+3] * secsize)
        pos = pos + 6
        n = n + 1
    ovl_count = n
    print(f"{ovl_count} overlays")
    print("   addr  len  reloc  size ")
    for i in range(ovl_count):
        print(f"  {ovl_addr[i]:06x} {ovl_len[i]:04x} {ovl_reloc[i]:06x} {ovl_reloc[i]-ovl_addr[i]:06x}")
    

def dump_reloc(f_in, reloc):
    global relocs
    f_in.seek(reloc)
    relocs={}
    n = 0
    print(f"  relocs at {reloc:04x}")
    while True:
        buf = f_in.read(4)
        if not buf:
            break
        addr = buf[0] << 8 | buf[1]
        mask = buf[2] << 8 | buf[3]
        if mask == 0xffff:
            break
        relocs[addr] = mask
        n = n + 1
    print(f"  {n} relocations")

def dump_instr(fpos, rpos, wpos, buf, reloc):
    val1 = buf[0]
    val2 = buf[1]
    s = ""
    c = ""
    if val1 & 0xe0 == 0:
        addr = ((val1 & 0x1f) << 8 | val2)
        s = f"SAI {addr:04x}"
        target = (wpos & 0xe000) | addr
        c = f"jump {target:04x}"
    elif val1 & 0xf0 == 0x20:
        x = val1 & 0xf
        y = val2
        s = f"AMD A{x:02},C{y:02x}"
        c = f"[{y:02x}] := A{x}"
    elif val1 & 0xf0 == 0x30:
        x = val1 & 0xf
        y = val2
        s = f"MAD A{x:02},C{y:02x}"
        c = f"A{x} := [{y:02x}]"
    elif val1 & 0xf0 == 0x40:
        y = val1 & 0xf
        x = val2
        s = f"SADE {y:01x} {x:02x}"
    elif val1 & 0xf0 == 0x70:
        x = val1 & 0xf
        y = val2
        s = f"CRTA A{x:02},C{y:02x}"
        c = f"A{x:02} := 0x{y:02x}"
    elif val1 & 0xf0 == 0x50:
        x = val1 & 0xf
        y = val2
        s = f"CRTB B{x:02},C{y:02x}"
        c = f"B{x:02} := 0x{y:02x}"
    elif val1 & 0xf8 == 0x60:
        x = val1 & 0x7
        addr = val2
        target = (wpos & 0xff00) | addr
        s = f"SAD0 {x},{addr:02x}"
        c = f"br D{x}=0,{target:04x}"
    elif val1 & 0xf8 == 0x68:
        x = val1 & 0x7
        addr = val2
        target = (wpos & 0xff00) | addr
        s = f"SAD1 {x},{addr:02x}"
        c = f"br D{x}=1,{target:04x}"
    elif val1 in opcode:
        x = val2 >> 4
        y = val2 & 0xf
        info = opcode[val1]
        opx = info[2]
        opy = info[3]
        if opx == 'M' and x >= 12:
            opx = 'A'
        argx = f"{opx}{x}"
        argy = ""
        argd = ""
        arg = argx
        if opy != '':
            argy = f"{opy}{y}"
            arg = f"{argx},{argy}"
        if opx == 'D':
            arg = f"{val2:02x}"
            argd = f"0x{val2:02x}"
        s = f"{info[1]} {arg}"
        c = info[4].format(argx=argx, argy=argy, argd=argd)
    # print(f"{fpos:04x}: {rpos:06x}: {val1:02x} {val2:02x}  {s:10}  {reloc}")
    print(f"{fpos:04x}: {wpos:04x}: {val1:02x} {val2:02x}  {s:16} {c:20} {reloc}")

def dump_overlay(f_in, start, end):
    f_in.seek(start)
    fpos = start
    rpos = 0
    wpos = 0
    while fpos < end:
        buf = f_in.read(2)
        if len(buf) < 2:
            break
        r = ""
        if rpos in relocs:
            r = f"mask {relocs[rpos]:04x}"
        dump_instr(fpos, rpos, wpos, buf, r)
        fpos = fpos + 2
        rpos = rpos + 2
        wpos = wpos + 1
        
def dump_overlays(f_in):
    print(f"...{ovl_count}")
    for i in range(ovl_count):
        print(f"==== Overlay {i}")
        dump_reloc(f_in, ovl_reloc[i])
        dump_overlay(f_in, ovl_addr[i], ovl_reloc[i])
        
def dump_all(f_in, f_dis):
    dis_fpos_re = re.compile(r"([0-9A-Fa-f]+):")
    dis_info_re = re.compile(r"; ")
    if f_dis:
        dpos = -1
    else:
        dpos = None
    fpos = 0
    rpos = 0
    wpos = 0
    while True:
        # before fpos, at dpos
        if dpos is not None and dpos < fpos:
            # read dis:
            while True:
                line = f_dis.readline()
                if line == "":
                    # eof
                    dpos = None
                    break
                line = line.rstrip('\n')
                m = dis_fpos_re.match(line)
                if m:
                    dpos = int(m.group(1), 16)
                    ## print("<<<== ", dpos)
                    break
                elif dis_info_re.match(line):
                    # never replicate info
                    pass
                else:
                    print(line)
        else:
            # read in
            if fpos in org:
                wpos = org[fpos]
                print(f"; org")
            buf = f_in.read(2)
            if len(buf) < 2:
                break
            dump_instr(fpos, rpos, wpos, buf, "")
            fpos = fpos + 2
            rpos = rpos + 2
            wpos = wpos + 1


fname = args.infile.name
print("; ---- dump:", os.path.basename(fname))

if args.overlay:        
    dump_header(args.infile)
    dump_overlays(args.infile)
else:
    dump_all(args.infile, args.disasm)

