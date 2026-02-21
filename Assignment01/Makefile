CC=gcc
CFLAGS=-Wall -g
LIBS=-lssl -lcrypto

all: server client rclient

server: server.c
	$(CC) $(CFLAGS) -o server server.c $(LIBS)

client: client.c
	$(CC) $(CFLAGS) -o client client.c $(LIBS)

rclient: rclient.c
	$(CC) $(CFLAGS) -o rclient rclient.c $(LIBS)

clean:
	rm -f server client rclient *.o
