all: server.c client.c
	gcc server.c -o serverout -lm
	gcc client.c -o clientout -lcrypto -lssl

