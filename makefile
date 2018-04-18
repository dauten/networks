all: server.c client.c
	gcc server.c -o serverout -lm -lcrypto -lssl
	gcc client.c -o clientout -lcrypto -lssl


