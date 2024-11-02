CC = gcc
CFLAGS = -Wall -Wextra -O3 -flto -fomit-frame-pointer -msse -msse2 -msse3 -mmmx -m3dnow

TARGET = unseal

all: $(TARGET) tests

$(TARGET): unseal.c
	$(CC) $(CFLAGS) -o $@ $<

tests:
	$(CC) $(CFLAGS) -o tests/loop tests/loop.c
	$(CC) $(CFLAGS) -o tests/testseal tests/test.c

clean:
	rm -f $(TARGET)
	rm -f tests/testseal tests/loop
	rm -f *.o

.PHONY: all clean tests