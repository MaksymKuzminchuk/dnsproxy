CC=gcc

all: dnsproxy

dnsproxy: dnsproxy.c
	$(CC) dnsproxy.c -o dnsproxy

clean:
	rm -rf *.o dnsproxy
