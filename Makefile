SRCDIR   = src
BUILDDIR = build
CC       = clang

# Resolve SDK explicitly — default sysroot can point at a missing CLT SDK
SDK_PATH := $(shell xcrun --show-sdk-path 2>/dev/null)
ifneq ($(SDK_PATH),)
CFLAGS   = -Wall -O2 -isysroot $(SDK_PATH)
else
CFLAGS   = -Wall -O2
endif

# UNIVERSAL=1 → arm64 + x86_64 fat binaries (for Intel targets)
ifeq ($(UNIVERSAL),1)
ARCHS     = -arch arm64 -arch x86_64
else
ARCHS     =
endif

DAEMON_SRC   = $(SRCDIR)/daemon/helper_daemon.m
CLIENT_SRC   = $(SRCDIR)/client/helper_client.m

DAEMON_BIN   = $(BUILDDIR)/daemon
CLIENT_BIN   = $(BUILDDIR)/client

DAEMON_FRAMEWORKS = -framework Foundation -framework Security \
                    -framework CoreGraphics -framework ImageIO \
                    -framework AppKit
DAEMON_LIBS       = -lsqlite3
CLIENT_FRAMEWORKS = -framework Foundation

.PHONY: all clean

all: $(DAEMON_BIN) $(CLIENT_BIN)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(DAEMON_BIN): $(DAEMON_SRC) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(ARCHS) -o $@ $< $(DAEMON_FRAMEWORKS) $(DAEMON_LIBS)

$(CLIENT_BIN): $(CLIENT_SRC) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(ARCHS) -o $@ $< $(CLIENT_FRAMEWORKS)

clean:
	rm -rf $(BUILDDIR)
