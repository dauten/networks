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
#include <openssl/sha.h>
#include <openssl/x509v3.h>

//takes a string and converts it to a string of its SHA1 digest
void SHA1ToString(char* str, char targ[]){

	unsigned char hash[SHA_DIGEST_LENGTH];
	
	SHA1(str, strlen(str), hash);	//apply SHA to input string storing digest in buffer
	sprintf(targ, "");		//instantiate empty string array
	for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
		//iterate through ther digest translating it from hex to the corresponding ASCII in our destination
		sprintf(targ, "%s%02x", targ, hash[i]);
	}	

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

	struct hostent *host;
	struct sockaddr_in addr;

	if ( (host = gethostbyname(SERVER)) == NULL )
		{
		perror(SERVER);
		abort();
	}
	tcpSock = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if ( connect(tcpSock, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		close(tcpSock);
		perror(SERVER);
		abort();
	}


	//now socket is set up.  We'll inform user SSL time is now and use socket to make secure connection

	printf("About to configure and negotiate SSL\n");

	// create variables and load in openssl
	SSL_CTX *context;
	SSL *ssl;
	SSL_library_init();

	// load functions and create our context, printing error message on failure
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	SSL_METHOD *method;
	method = TLSv1_2_client_method();
	if((context=SSL_CTX_new(method))==NULL) printf("context may not have been setup correctly\n");
	
	// create our SSL conenction using our context
	ssl=SSL_new(context);
	SSL_set_fd(ssl, tcpSock);

	// see if we connect
	if(SSL_connect(ssl) == -1) printf("SSL connection may have failed\n");
	printf("If we got no errors then we are allegedly connected with %s encryption.  We will send a msg to test\n", SSL_get_cipher(ssl));
	
	// to double check, we will get the certificate from the server
	X509 *cert = SSL_get_peer_certificate(ssl);
	if(cert != NULL){
		printf("Certificate confirmed\n");
	}
	else{
		printf("Unable to obtain certificate\n");
	}

	//as stated above, we are good to go if there were no error messages.  even if there was an error we won't
	//exit but things would break later
	printf("We should be connected and ready to send encypted messages now\n");

	char* split;
	char msg[10];



	//main listen/reply loop
	while(flag)
	{
		//get and print input, copy it into a temp and tokenize it.
		SSL_read(ssl, input, 512);
		printf("client: received '%s'\n",input);
		memcpy(msg, input, 64);
		split = strtok(msg, " ");

		//if permission to leave
		if(strcmp(input, "200 BYE")==0){
			flag=0;
		}


		//right now get our reply from user and format to remove endline (\n is messy for our parsing)
		printf("input:\n");
		fgets(input, 64, stdin);
		for(int i = 0; i < 64; i++){
			if(input[i] == '\n'){
				input[i] = '\0';
				i = 64;
				break;
			}
		} //end for

		//if server told us to reply with a username or password we need to encode it before we send it
		if(strcmp(split, "334")==0){

			//for more comments see encoding section in server.
			//general idea is we make a pipe with memory and an encoding function
			//that we'll push our username/password through and it'll spit
			//out it in base64
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
		SSL_write(ssl, input, 100);

} //end while

	close(tcpSock);

	return 0;

} //end main


