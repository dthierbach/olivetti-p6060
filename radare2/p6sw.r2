# r2 -a p6060 extract/system/P6SW

fs balr
f balr.r10_1f9a 184 @ 0x1f9a
f balr.r7_3996 (0x3dbc-0x3996)@ 0x3996

CC segment0011 @0x2300
Cd 1 @0x2300
Cd 1 @0x2301
Cd 2 @0x2302
 
s 0x1f88
pd

