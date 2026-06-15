CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDLIBS = -lm
TARGET = tp4
SRC = main.c abr.c

all: $(TARGET)

$(TARGET): $(SRC) abr.h
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDLIBS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
