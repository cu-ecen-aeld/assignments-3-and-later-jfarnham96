CC = gcc
CFLAGS = -pthread

ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
		CC = $(CROSS_COMPILE)gcc
endif

all:
		$(CC) $(CFLAGS) -g aesdsocket.c -o aesdsocket

clean:
		rm -f aesdsocket

