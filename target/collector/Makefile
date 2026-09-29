CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c99 -D_GNU_SOURCE -Iinclude
LDFLAGS ?=

SRCS = src/collector.c src/main.c
OBJS = $(SRCS:.c=.o)
TARGET = dynamicstate-collector

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/

.PHONY: all clean install
