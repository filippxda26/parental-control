CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
all: parental-control
parental-control: src/parental-control.c src/parental-control-web.c
	$(CC) $(CFLAGS) -o $@ $^ -ljson-c -pthread
clean:
	rm -f parental-control parental-control-web
