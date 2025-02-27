CC = gcc

OBJCS = client.c 
OBJCSS = server.c

CFLAGS = -g -Wall

LIBS = -lcjson -lssl -lcrypto

all: client server

client: $(OBJCS)
	$(CC) $(CFLAGS) -o $@ $(OBJCS) $(LIBS)

server: $(OBJCSS)
	$(CC) $(CFLAGS) -o $@ $(OBJCSS) $(LIBS)

clean:
	@rm -f client server
