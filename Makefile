# Comments here


INSTALL_PREFIX=

ASTERISK_HEADER_DIR=$(INSTALL_PREFIX)/usr/include

PROC=$(shell uname -m)

DEBUG=-g3

OPTIMIZE=-O6

INCLUDE=-I$(ASTERISK_HEADER_DIR)

CFLAGS=-pipe -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations 
CFLAGS+=$(DEBUG) $(INCLUDE) -D_REENTRANT -D_GNU_SOURCE $(OPTIMIZE)
CFLAGS+=$(shell if $(CC) -march=$(PROC) -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-march=$(PROC)"; fi)
CFLAGS+=-fomit-frame-pointer -Wno-missing-prototypes -Wno-missing-declarations
CFLAGS+=-DCRYPTO -fPIC -c 

CC=gcc

INSTALL=install

OBJECTS=res_zonkey_mwi.o

SHAREDOS=res_zonkey_mwi.so

all: res_zonkey_mwi.o res_zonkey_mwi.so

res_zonkey_mwi.o: res_zonkey_mwi.c
	$(CC) $(CFLAGS) -o res_zonkey_mwi.o res_zonkey_mwi.c

res_zonkey_mwi.so: res_zonkey_mwi.o
	$(CC) -shared -Xlinker -x -o res_zonkey_mwi.so res_zonkey_mwi.o

install: all
	$(INSTALL) -m 755 res_zonkey_mwi.so /usr/lib/asterisk/modules/

reinstall: clean all install

clean:
	rm -f *.o *.so


