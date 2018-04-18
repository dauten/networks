all: server.c client.c
<<<<<<< HEAD
	gcc server.c -o serverout -lm
	gcc client.c -o clientout -pthread
=======
	gcc server.c -o serverout -lm -lcrypto -lssl
	gcc client.c -o clientout -lcrypto -lssl
>>>>>>> PR03

