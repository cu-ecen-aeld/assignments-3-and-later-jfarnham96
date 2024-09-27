CC ?= gcc
CFLAGS ?= -pthread -lrt -g

ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
		CC ?= $(CROSS_COMPILE)gcc
endif

all:
		$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket

clean:
		rm -f aesdsocket

