CC ?= gcc
CFLAGS ?= -pthread -lrt -g
LDFLAGS ?= 

USE_AESD_CHAR_DEVICE ?= 1
CFLAGS += -DUSE_AESD_CHAR_DEVICE=$(USE_AESD_CHAR_DEVICE)

ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
		CC ?= $(CROSS_COMPILE)gcc
endif

all:
		$(CC) $(LDFLAGS) $(CFLAGS) aesdsocket.c -o aesdsocket

clean:
		rm -f aesdsocket

