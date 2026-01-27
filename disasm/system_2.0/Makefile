FW=../../tools/fw.py
SRCDIR=../../extract/system_2.0

#  --overlay ../../extract/system_2.0/P6FWO > firmware-over.txt

#  ../../tools/fw.py ../../extract/system_2.0/P6FWR2.0

all: firmware-main.new firmware-over.new

firmware-main.new: $(FW) firmware-main.txt
	$(FW) $(SRCDIR)/P6FWR2.0 --disasm firmware-main.txt > firmware-main.new

firmware-over.new: $(FW) firmware-over.txt
	$(FW) $(SRCDIR)/P6FWR2.0 --overlay --disasm firmware-over.txt > firmware-over.new
