CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c99 -D_GNU_SOURCE -Iinclude
LDFLAGS ?=
VERSION := $(shell cat VERSION 2>/dev/null || echo dev)
CFLAGS += -DCOLLECTOR_VERSION=\"$(VERSION)\"

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

# ---- Static per-architecture builds: `make dist` -> dist/<arch>/dynamicstate-collector
# arch:cross-compiler pairs; an arch is skipped (and reported) if its compiler is missing.
DIST_ARCHES = aarch64:aarch64-linux-gnu-gcc x86_64:x86_64-linux-gnu-gcc
DIST_CFLAGS = -O2 -Wall -Wextra -std=c99 -D_GNU_SOURCE -Iinclude -DCOLLECTOR_VERSION=\"$(VERSION)\"

dist:
	@built=""; skipped=""; failed=""; \
	for pair in $(DIST_ARCHES); do \
	  arch=$${pair%%:*}; cc=$${pair#*:}; \
	  if command -v $$cc >/dev/null 2>&1; then \
	    mkdir -p dist/$$arch; \
	    if $$cc $(DIST_CFLAGS) -static -o dist/$$arch/$(TARGET) $(SRCS); then \
	      built="$$built $$arch"; else failed="$$failed $$arch"; fi; \
	  else skipped="$$skipped $$arch($$cc)"; fi; \
	done; \
	echo "dist: built:$${built:- none}"; \
	echo "dist: SKIPPED (cross compiler not installed):$${skipped:- none}"; \
	[ -z "$$failed" ] || { echo "dist: FAILED:$$failed"; exit 1; }

clean:
	rm -f $(foreach a,aarch64 x86_64,dist/$(a)/$(TARGET))
	rm -f $(OBJS) src/test_crypto.o $(TARGET) $(TEST_CRYPTO)

install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/

.PHONY: all clean install dist
