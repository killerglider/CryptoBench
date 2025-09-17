# Compiler
CC = gcc

# Compiler flags
# -Iinclude tells the compiler to look for header files in the 'include' directory
# -Wall enables all common warnings
# -O3 is a high level of optimization
# -D_POSIX_C_SOURCE=199309L enables POSIX.1b functions like clock_gettime
CFLAGS = -Iinclude -Wall -O3 -D_POSIX_C_SOURCE=199309L

# Linker flags
# -lcrypto links the OpenSSL crypto library
# -lm links the math library (good practice for timing functions)
# -lrt links the real-time library (needed for clock_gettime on some systems)
LDFLAGS = -lcrypto -lm -lrt

# Find all .c files in the src directory and its subdirectories
SRCS = $(wildcard src/*.c src/aes/*.c src/ascon/*.c)

# Replace the .c extension with .o to get the object file names
OBJS = $(SRCS:.c=.o)

# The final executable name
TARGET = benchmark

# The default target, called when you just type 'make'
all: $(TARGET)

# Rule to link all the object files into the final executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Rule to compile a .c file into a .o file
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean up build files
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean