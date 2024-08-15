CC = gcc

ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
		CC = $(CROSS_COMPILE)gcc
endif

all:
		$(CC) writer.c -o writer

clean:
		rm writer

