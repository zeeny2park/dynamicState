CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c99 -D_GNU_SOURCE -Iinclude
LDFLAGS ?=

SRCS = src/collector.c src/main.c src/sha256.c
OBJS = $(SRCS:.c=.o)
TARGET = dynamicstate-collector
TEST_CRYPTO = test_crypto

all: $(TARGET) $(TEST_CRYPTO)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(TEST_CRYPTO): src/test_crypto.o src/sha256.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) src/test_crypto.o $(TARGET) $(TEST_CRYPTO)

install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/

.PHONY: all clean install
