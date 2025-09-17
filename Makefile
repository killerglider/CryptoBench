# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Iinclude -IC:/msys64/mingw64/include -Wall -O3 -D_POSIX_C_SOURCE=199309L

# Linker flags (conditional: -lrt only on Linux)
ifeq ($(OS),Windows_NT)
    LDFLAGS = -LC:/msys64/mingw64/lib -lssl -lcrypto -lm
else
    LDFLAGS = -lssl -lcrypto -lm -lrt
endif

# Source files
SRCS = $(wildcard src/*.c src/aes/*.c src/ascon/*.c)

# Object files
OBJS = $(SRCS:.c=.o)

# Target
TARGET = benchmark

# Default target
all: $(TARGET)

# Link step
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile step
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
