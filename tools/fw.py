#!/usr/bin/env python3

import sys

import argparse

parser = argparse.ArgumentParser(description='Decode image disk file')
parser.add_argument(dest='infile', type=argparse.FileType('rb'))
args = parser.parse_args()

print("---- dump")

class EOF(Exception):
    pass

opcode={}
opcode[0xc9] = 'SEDI'
opcode[0x88] = 'AMIP'
opcode[0x8c] = 'BMIP?'
opcode[0xa8] = 'AMI'
opcode[0xac] = 'BMI?'
opcode[0xf0] = 'ALFA'
opcode[0x50] = 'RESET'

def dump_all(f_in):
    pos = 0
    while True:
        buf = f_in.read(2)
        if len(buf) < 2:
            break
        val1 = buf[0]
        val2 = buf[1]
        s = ''
        if val1 in opcode:
            s = opcode[val1]
        print(f"{pos:04x}: {val1:02x} {val2:02x} {s}")
        pos = pos + 2

dump_all(args.infile)

