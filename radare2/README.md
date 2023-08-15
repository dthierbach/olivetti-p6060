# radare2-p6060
Radare2 plugin for the Olivetti P6060 ISA

Symlink library to radare plugin location
Get location with `r2pm -I`

    cd ~/.local/share/radare2/plugins
    ln -s ~/Documents/repos/p6060/olivetti-p6060/radare2/p6060_dis.dylib .


cd extract/system

r2 -a puce P6FWR4.1 
V p