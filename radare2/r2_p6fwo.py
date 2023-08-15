#!/usr/bin/env python3

# produce radare commands for overlay firmware

import sys
from struct import unpack_from

name = '../extract/system/P6FWO'

def analyze(fw):
    pos = 0
    ovl = 1
    while True:
        start_sct = fw[pos+1]
        if start_sct == 0:
            break
        len_sct   = fw[pos+2]
        reloc_sct = fw[pos+3]
        start = start_sct * 0x80
        reloc = (start_sct + reloc_sct) * 0x80
        print(f"CC ==== Overlay {ovl} @ {start}")
        print(f"Cf 6 wbbbb start_sct len_sct tab_sct unk unk @ {pos}")
        i = (len_sct - reloc_sct) * 0x80 // 2
        print(f"CC ==== Reloc {ovl} @ {reloc}")
        print(f"Cd 2 {i} @ {reloc}")
        i = reloc
        while True:
            rpos, rtype = unpack_from('>HH', fw, i)
            if rtype == 0xffff:
                break
            print(f"CC reloc {rtype:04x} @ {start+rpos}")
            i += 4
        ovl += 1
        pos += 6

with open(name, 'rb') as file:
    fw = file.read()
    analyze(fw)
