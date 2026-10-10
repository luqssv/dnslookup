CC ?= gcc

CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude

LDFLAGS ?=

LDLIBS ?= -lresolv -lpthread


TARGET = dnslookup


SRC = \
	src/main.c \
	src/dns.c \
	src/ui.c \
	src/process.c


OBJ = $(SRC:.c=.o)


all: $(TARGET)


$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	rm -f $(OBJ) $(TARGET)


install: $(TARGET)
	install -Dm755 $(TARGET) /usr/local/bin/$(TARGET)


.PHONY: all clean install