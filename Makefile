# Compiler and Flags
CC = gcc
CFLAGS = -Wall -I/usr/include/bpf
LDFLAGS = -lbpf -lm -lpthread -lrt

# Sources and Objects
SRC = main.c cJSON.c
OBJ = main.o cJSON.o

# Executables
TARGETS = noisecatcher

# Default target
all: $(TARGETS)

# Build noisecatcher
noisecatcher: main.o cJSON.o
	$(CC) $(CFLAGS) -o noisecatcher main.o cJSON.o $(LDFLAGS)

# Rule to compile .c files to .o
%.o: %.c
	$(CC) $(CFLAGS) -c $<

# Clean up generated files
clean:
	rm -f *.o $(TARGETS) *.out
