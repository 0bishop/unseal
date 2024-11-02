CC = gcc
CFLAGS = -Wall -Wextra -O3 -flto -fomit-frame-pointer -msse -msse2 -msse3 -mmmx -m3dnow

TARGET = runtime_unseal
TARGET_1 = static_unseal

all: $(TARGET) $(TARGET_1) tests

$(TARGET): runtime/unseal.c
	$(CC) $(CFLAGS) -o $@ $<

$(TARGET_1): static/unseal.c
	$(CC) $(CFLAGS) -o $@ $<

tests:
	$(CC) $(CFLAGS) -o tests/loop tests/loop.c
	$(CC) $(CFLAGS) -o tests/testseal tests/test.c

clean:
	rm -f $(TARGET) $(TARGET_1)
	rm -f tests/testseal tests/loop patched_*
	rm -f *.o

.PHONY: all clean tests