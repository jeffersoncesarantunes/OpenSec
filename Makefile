# OpenSec Makefile (Portable BSD/Linux + Hardened)
# Live Forensic Process Security Analyzer
# Version 2.0

# Detect OS
UNAME_S := $(shell uname -s)

# Compiler detection (OpenBSD prefers egcc)
ifeq ($(UNAME_S),OpenBSD)
	CC ?= egcc
else
	CC ?= clang
endif

# If selected compiler doesn't exist, fallback to cc
CC := $(shell command -v $(CC) 2>/dev/null || echo cc)

# Base flags
CFLAGS = -Wall -Wextra -Wpedantic -Iinclude -O2 -g
LDFLAGS =
HARDENING =
OS_LIBS =

# OS-specific configuration
ifeq ($(UNAME_S),OpenBSD)
	HARDENING += -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2
	LDFLAGS += -Wl,-z,relro -Wl,-z,now -pie
	OS_LIBS += -lkvm
endif

ifeq ($(UNAME_S),FreeBSD)
	HARDENING += -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2
	LDFLAGS += -Wl,-z,relro -Wl,-z,now -pie
	OS_LIBS += -lkvm
endif

ifeq ($(UNAME_S),Linux)
	HARDENING += -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2
	LDFLAGS += -Wl,-z,relro -Wl,-z,now -pie
endif

CFLAGS += $(HARDENING)
LDFLAGS += $(OS_LIBS)

# Directories
SRCDIR = src
OBJDIR = obj
BINDIR = bin
COREDIR = $(SRCDIR)/core
UTILDIR = $(SRCDIR)/utils
MODULEDIR = $(SRCDIR)/modules

# Source files
SOURCES = \
	$(SRCDIR)/main.c \
	$(COREDIR)/process_scanner.c \
	$(COREDIR)/pledge_analyzer.c \
	$(COREDIR)/wx_monitor.c \
	$(COREDIR)/sysctl_hardening.c \
	$(UTILDIR)/logger.c \
	$(UTILDIR)/bsd_utils.c \
	$(MODULEDIR)/advanced_scan.c

# Robust object generation (portable)
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
TARGET = $(BINDIR)/opensec

# Default target
all: dirs $(TARGET)
	@echo "✅ OpenSec build complete!"
	@echo "System: $(UNAME_S)"
	@echo "Compiler: $(CC)"
	@ls -la $(BINDIR)/

# Create necessary directories dynamically
dirs:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(OBJDIR)/core
	@mkdir -p $(OBJDIR)/utils
	@mkdir -p $(OBJDIR)/modules
	@mkdir -p $(BINDIR)

# Link final binary
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# Pattern rule (robust object builder)
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -rf $(OBJDIR) $(BINDIR)
	@echo "🧹 Clean complete"

# Debug info
debug:
	@echo "=== OpenSec Debug Information ==="
	@echo "System: $(UNAME_S)"
	@echo "Compiler: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"
	@echo "SOURCES: $(SOURCES)"
	@echo "OBJECTS: $(OBJECTS)"
	@echo "TARGET: $(TARGET)"
	@echo "================================="

# Install
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/opensec
	@echo "✅ OpenSec installed to /usr/local/bin/opensec"

# Uninstall
uninstall:
	rm -f /usr/local/bin/opensec
	@echo "✅ OpenSec removed from /usr/local/bin/"

.PHONY: all clean dirs debug install uninstall
