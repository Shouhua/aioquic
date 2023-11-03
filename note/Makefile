# sudo apt install inotify-tools
# while inotifywait -q -e modify fd.c; do echo -e '\n'; make; done

SRC := $(wildcard *.c)
TARGET := $(patsubst %.c, %, ${SRC})

.PHONY: all clean

all: ${TARGET}

%: %.c
	gcc -Wall -Wextra -pedantic -g -o $@ $^ -lssl -lcrypto 

clean:
	rm -f ${TARGET}
