NAME=p6060_dis
R2_PLUGIN_PATH=$(shell r2 -hh|grep R2_LIBR_PLUGINS|awk '{print $$2}')
CFLAGS_ASM=-g -fPIC $(shell pkg-config --cflags r_asm)
LDFLAGS_ASM=-shared $(shell pkg-config --libs r_asm)
CFLAGS_ANAL=-g -fPIC $(shell pkg-config --cflags r_anal)
LDFLAGS_ANAL=-shared $(shell pkg-config --libs r_anal)
OBJS=$(NAME).o
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
LIB=$(NAME).$(SO_EXT)

all: p6060_dis.$(SO_EXT) p6060_ana.$(SO_EXT)

clean:
	rm -f *.$(SO_EXT) *.o

p6060_dis.$(SO_EXT): p6060_dis.c
	$(CC) $(CFLAGS_ASM) $(LDFLAGS_ASM) p6060_dis.c -o p6060_dis.$(SO_EXT)

p6060_ana.$(SO_EXT): p6060_ana.c
	$(CC) $(CFLAGS_ANAL) $(LDFLAGS_ANAL) p6060_ana.c -o p6060_ana.$(SO_EXT)

# install:
# 	cp -f $(LIB) $(R2_PLUGIN_PATH)
# 
# uninstall:
# 	rm -f $(R2_PLUGIN_PATH)/$(LIB)
