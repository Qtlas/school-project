CC = gcc
CFLAGS = -Wall -Wextra -std=c11

all: abr

abr: abr.c
	$(CC) $(CFLAGS) -o $@ $<

run: abr
	./abr

clean:
	rm -f abr

.PHONY: all run clean
