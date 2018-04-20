/**
* Author:  Dale Auten
* Modified: 2/14/18
* Desc: Client Side half of a project to communicate through sockets bound to ports on a linux machine.
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


#include <openssl/ssl.h>
#include <openssl/err.h>
#include "openssl/bio.h"
#include <arpa/inet.h>


//function from beej's guide
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	//declaration
	int tcpSock, numbytes;  
	char buf[128];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	char *SERVER = argv[1];
	uint PORT = atoi(argv[2]);
	char input[64];
	int flag = 1;

	// check if user gave needed args
	if (argc != 3) {
		fprintf(stderr,"usage: client <hostname> <port>\n");
		exit(1);
	}

	//try to set up the port.  from beej's guide
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((rv = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((tcpSock = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}
		if (connect(tcpSock, p->ai_addr, p->ai_addrlen) == -1) {
			close(tcpSock);
			perror("client: connect");
			continue;
		}

		break;
	}//end for


	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),s, sizeof s);

	freeaddrinfo(servinfo);


	send(tcpSock, "HANDSHAKE", 16, 0);
	
	char* split;
	char msg[10];




	while(flag)
	{
		recv(tcpSock, input, 100, 0);
	//	buf[numbytes] = '\0';
		printf("client: received '%s'\n",input);
		memcpy(msg, input, 64);
		split = strtok(msg, " ");

		if(strcmp(input, "200 BYE")==0){
			flag=0;
		}


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
		if(strcmp(split, "334")==0){
			split = strtok(input, " ");
			BIO *bmem, *b64;
			BUF_MEM *bptr;

			b64 = BIO_new(BIO_f_base64());
			bmem = BIO_new(BIO_s_mem());
			b64 = BIO_push(b64, bmem);
			BIO_write(b64, split, strlen(split));
			BIO_flush(b64);
			BIO_get_mem_ptr(b64, &bptr);
			char *buff = (char *)malloc(bptr->length);
			memcpy(buff, bptr->data, bptr->length-1);
			buff[bptr->length-1] = 0;
			BIO_free_all(b64);
			sprintf(input, "%s",buff);
		}


		//send, recieve, and output
		send(tcpSock, input, 100, 0);

} //end while

	close(tcpSock);

	return 0;

} //end main

