FW=../../tools/fw.py
SRCDIR=../../rom/system/

#  ../../tools/fw.py ../../extract/system_2.0/P6FWR2.0

all: romca.new carom.new

romca.new: $(FW) romca.txt
	$(FW) --rom $(SRCDIR)/romca/romca.bin --disasm romca.txt > romca.new

carom.new: $(FW) carom.txt
	$(FW) --rom $(SRCDIR)/carom/carom.bin --rom --disasm carom.txt > carom.new
