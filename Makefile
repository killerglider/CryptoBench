# Compiler and Target Executable Name
CC = gcc
TARGET = benchmark

# --- MANUAL PATH CONFIGURATION ---
# IMPORTANT: You must change these paths to match your system's OpenSSL installation.

# Path to the OpenSSL 'include' directory (for header files like evp.h)
# Example for MinGW/MSYS2 on Windows.
OPENSSL_INC_PATH = C:/msys64/mingw64/include

# Path to the OpenSSL 'lib' directory (for the library files)
# Example for MinGW/MSYS2 on Windows.
OPENSSL_LIB_PATH = C:/msys64/mingw64/lib


# --- Flags (No need to edit below this line) ---

# Compiler Flags:
# -I is used to add include directories.
CFLAGS = -Iinclude -I$(OPENSSL_INC_PATH) -Wall -O3 -march=armv8-a+simd -std=c11

# Linker Flags:
# -L is used to add library search directories.
LDFLAGS = -L$(OPENSSL_LIB_PATH)

# Libraries to Link:
# These are the actual libraries we need. This is the crucial part for the linker.
# The order is important: your code uses ssl, which uses crypto.
LDLIBS = -lssl -lcrypto -lm


# --- Source Files ---

# Automatically find all .c files in the src directory and its subdirectories
SRCS = $(wildcard src/*.c src/aes/*.c src/ascon/*.c)
# Create a list of corresponding .o object files
OBJS = $(SRCS:.c=.o)


# --- Build Rules ---

# The default target, called when you just run 'make'
all: $(TARGET)

# Linking Rule:
# This command links all your compiled object files ($^) into the final executable ($@).
# CRUCIAL: The $(LDLIBS) are placed at the very end of the command.
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Compilation Rule:
# This is how any .c file is compiled into a .o object file.
# It uses the CFLAGS to find headers (like openssl/evp.h).
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean Rule: Removes all generated files
clean:
	rm -f $(OBJS) $(TARGET)

# Phony target to prevent conflicts with a file named 'all' or 'clean'
.PHONY: all clean