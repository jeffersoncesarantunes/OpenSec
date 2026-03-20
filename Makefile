CC = cc
CFLAGS = -Wall -Wextra -O2 -I./include -I/usr/local/include
LDFLAGS = -lkvm
TARGET = bin/opensec
SRC = src/main.c src/engine.c
BIN_DIR = bin

all: $(TARGET)

$(TARGET): $(SRC)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

install: all
	install -m 4755 -o root -g wheel $(TARGET) /usr/local/bin/opensec

clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean install
