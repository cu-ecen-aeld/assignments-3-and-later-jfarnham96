CC ?= gcc
CFLAGS ?= -pthread -lrt -g
LDFLAGS ?= 

ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
		CC ?= $(CROSS_COMPILE)gcc
endif

all:
		$(CC) $(LDFLAGS) $(CFLAGS) aesdsocket.c -o aesdsocket

clean:
		rm -f aesdsocket

