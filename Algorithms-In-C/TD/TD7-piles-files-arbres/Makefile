CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDLIBS = -lm

PROGRAMS = pile file arbre

all: $(PROGRAMS)

pile: pile.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

file: file.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

arbre: arbre.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(PROGRAMS)

.PHONY: all clean
