/**
* Author:  Dale Auten
<<<<<<< HEAD
* Modified: 3/27/18
* Desc: Client Side half of a project to communicate through sockets bound to ports on a linux machine.
=======
* Modified: 4/14/18
* Desc: Client Side half of a project to communicate through sockets bound to ports on a linux machine through TLS
>>>>>>> PR03
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


#include <pthread.h>

#include <arpa/inet.h>


#include <openssl/ssl.h>
#include <openssl/err.h>
#include "openssl/bio.h"


struct args_struct {
	int udpSock;
	struct sockaddr_in otherUDP;
	uint slen;
};

uint sendMessage(int udpSock, char *input, struct sockaddr_in otherUDP, uint slen, int depth);
void inputParser(int udpSock, struct sockaddr_in otherUDP, uint slen);
void *listener(void * args);

int main(int argc, char *argv[])
{

	char *SERVER = argv[1];
	uint PORT = atoi(argv[2]);
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

	char* split;
	char msg[10];

	while(flag)
	{
		BIO_read(bio, input, 100);
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
		BIO_write(bio, input, 100);

	} //end while

	BIO_free_all(bio);
	return 0;

	if(depth > 10){
		printf("Sorry, that message could not be delivered.  Try again later.");
		return 1;	// error return message
	}

	sendto(udpSock, input, 512 , 0 , (struct sockaddr *) &otherUDP, slen);
	memset(input,'\0', 512);
/*
	while(!ackFlag){
		sleep(1);
		//lack of ACK, resend.
		//it is ok if the server DID receive the message and an ACK is on the way,
		//as long as the server receives the message at some point its its job to
		//sort out duplicates, and we should receive the ACK meant for the first msg
		//for the second one we send
		return sendMessage(udpSock, input, otherUDP, slen, depth+1);
		//so long as we don't stack overflow or something we should exit the function call eventually so
		
	}

	ackFlag = 0;*/
	return 0;


}
