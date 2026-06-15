CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = tp3
SRC = main.c tp3.c

all: $(TARGET)

$(TARGET): $(SRC) tp3.h
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
