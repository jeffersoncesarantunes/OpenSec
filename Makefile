CC = cc
CFLAGS = -Wall -Wextra -I./include
LDFLAGS = -lkvm
TARGET = bin/opensec
SRC = src/main.c src/engine.c

all: $(TARGET)

$(TARGET): $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf bin
