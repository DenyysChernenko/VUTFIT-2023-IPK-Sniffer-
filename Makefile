# Compiler
CC=gcc
# Compiler flags
CFLAGS=-Wall -Wextra -g

# Library flags
LIBS=-lpcap

# Source files
SOURCES=main.c arguments_parse.c sniffer.c
# Object files
OBJECTS=$(SOURCES:.c=.o)
# Executable name
EXECUTABLE=ipk-sniffer

# Default rule
all: $(EXECUTABLE)

# Rule to compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to link object files into the executable
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

# Clean rule to remove object files and the executable
clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
