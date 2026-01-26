#!/usr/bin/env python3

# combine rom files

# carom:
# ../../../tools/rom.py 0 11a9a71f.bin dcb77b22.bin 

# romca
# ../../../tools/rom.py 0xc00 706e035f.bin 47f8b402.bin 799546a7.bin 33f1a400.bin 

import sys

outname="out.bin"

ofs = int(sys.argv[1], 0)
with open(outname, mode="wb") as outfile:
    for highname, lowname in zip(sys.argv[2::2], sys.argv[3::2]):
        print(f"Combining high={highname} low={lowname}")
        with open(highname, mode="rb") as highfile:
            with open(lowname, mode="rb") as lowfile:
                highfile.seek(ofs)
                lowfile.seek(ofs)
                while True:
                    highbuf = highfile.read(1)
                    lowbuf = lowfile.read(1)
                    if len(highbuf) < 1 or len(lowbuf) < 1:
                        break
                    outfile.write(highbuf)
                    outfile.write(lowbuf)
