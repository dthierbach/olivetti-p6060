# olivetti-p6060

This project containers disk images and reverse engineering information for the [Olivetti P6060](https://en.wikipedia.org/wiki/Olivetti_P6060).

## Floppy disk structure

The 8-inch floppy disks follow the IBM format, with ASCII instead of EBCDIC.

A system disk has datasets
- P6FWR`<version>`, the firmware (microcode)
- P6FRO, the firmware overlay
- P6SW, the software, i.e. the operating system.

A user disk, or a system disk with user data, has the dataset
- P6FSYS, which contains the P6060 libraries

A "dataset" is the IBM-terminology for a file.

The tool `vtoc` can be used to list those datasets on image dump.

The tool `catalog` can be used to list files inside the libraries.

## Firmware

The firmware is an interpreter for an instruction set very similar to the IBM/360.

## Operating System

The operating system is seperated into segments, which are loaded into memory as required.

