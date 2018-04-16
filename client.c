/**
* Author:  Dale Auten
* Modified: 4/14/18
* Desc: Client Side half of a project to communicate through sockets bound to ports on a linux machine through TLS
* Beej's Guide to Network Programming (https://beej.us/guide/bgnet/) was referenced heavily
* and certain lines were taken from the guide.  I have noted where.
**/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "openssl/bio.h"

int main(int argc, char *argv[])
{
	char *SERVER = argv[1];
	uint PORT = atoi(argv[2]);
	char input[64];
	int flag = 1;

	// check if user gave needed args
	if (argc != 3) {
		fprintf(stderr,"usage: client <hostname> <port>\n");
		exit(1);
	}

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	char ad[22];
	sprintf(ad, "%s:%d", SERVER, PORT);
	BIO *bio;
	bio = BIO_new_connect(ad);
	if(bio == NULL){
		printf("bio null\n");
		exit(1);
	}
	if(BIO_do_connect(bio) <= 0){
		printf("did not connect\n");
		exit(1);
	}

	printf("It must have connected properly\n");
	if(BIO_write(bio, "HANDSHAKE", 16) <= 0)
	{
		printf("msg not sent\n");
		exit(1);
	}



	//we expect an initial response from the server.
	BIO_read(bio, input, 100);
	printf("client: received '%s'\n",input);

	while(flag)
	{
		//input
		printf("input:\n");
		fgets(input, 64, stdin);
		for(int i = 0; i < 64; i++){
			if(input[i] == '\n'){
				input[i] = ' ';
				input[i+1] = '\n';
				input[i+2] = '\0';
				i = 64;
				break;
			}
		} //end for

		//send, recieve, and output
		BIO_write(bio, input, 100);
		BIO_read(bio, input, 100);
	//	buf[numbytes] = '\0';
		printf("client: received '%s'\n",input);

		if(strcmp(input, "200 BYE")==0){
			flag=0;
		}
	} //end while

	BIO_free_all(bio);
	return 0;

} //end main
