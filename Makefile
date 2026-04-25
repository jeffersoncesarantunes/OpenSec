CC = cc
CFLAGS = -Wall -Wextra -O2 -I./include -I/usr/local/include
LDFLAGS = -lkvm
TARGET = opensec
SRC = src/main.c src/engine.c

all: $(TARGET)
	@echo " ✅ Build complete: $(TARGET)"

$(TARGET): $(SRC)
	@$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

install: all
	install -m 4755 -o root -g wheel $(TARGET) /usr/local/bin/opensec

clean:
	@rm -f $(TARGET)
	@echo " 🧹 Cleaned up binary"

.PHONY: all clean install
