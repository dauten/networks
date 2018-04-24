/**
* Author:  Dale Auten
* Modified: 4/19/18
* Desc: Server Side half of a project to communicate through sockets bound to ports on a linux machine.
* Beej's Guide to Network Programming (https://beej.us/guide/bgnet/) was referenced heavily
* and certain lines were taken from the guide.  I have noted where.
**/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <math.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "openssl/bio.h"

#include <openssl/x509v3.h> 

//takes a string and converts it to a string of its SHA1 digest
void SHA1ToString(char* str, char targ[]){
	char st[200];
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(str, strlen(str), hash);
	sprintf(st, "");
	for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
		sprintf(st, "%s%02x", st, hash[i]);
	}	
	memcpy(targ, st, 200);

}

//two functions from beej's guide
void sigchld_handler(int s)
{
	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

		errno = saved_errno;
}
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


	
int main(int argc, char *args[])
{

	//declarations taken from beej's guide
	int sockfd, new_fd, numbytes;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;



	//check that the user included arguments then copy them into our ports
	if(argc != 2){
		printf("usage: server <tcp port>\n");
		exit(0);
	}
	char *tcpPort = args[1];
	char *udpPort = args[2];

	//the structure here is beej's but I've filled it with my own logic
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, tcpPort, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}
	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) {
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,sizeof(int)) == -1) {
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			continue;
		}

		break;
	}
	freeaddrinfo(servinfo); // all done with this structure
	if (p == NULL)  {
		exit(1);
	}

	if (listen(sockfd, 10) == -1) {
		perror("listen");
		exit(1);
	}
	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		exit(1);
	}


	SSL_CTX *context;
	SSL_library_init();

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	if((context=SSL_CTX_new(TLSv1_2_server_method()))==NULL) printf("context may not have been setup correctly\n");

	
	if ( SSL_CTX_use_certificate_file(context, "auten.crt", SSL_FILETYPE_PEM) <= 0 )
	{
		printf("We failed to get the certificate file\n");
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(context, "auten.key", SSL_FILETYPE_PEM) <= 0 )
	{
		printf("We failed to get the key file\n");
	}
	/* verify private key */
	if ( !SSL_CTX_check_private_key(context) )
	{
		printf("Key check failed\n");
	}

	

	while(1) 
	{  // main accept() loop

		printf("main loop entered\n\n");
		sin_size = sizeof their_addr;
		SSL *ssl;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			continue;
		}

		char buf[100];

		inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),s, sizeof s);
		printf("server: got connection from %s\n", s);


		ssl = SSL_new(context);
		SSL_set_fd(ssl, new_fd);
		
		if(SSL_accept(ssl) < 0) printf("We had some trouble accepting that client over SSL\n");
		// to double check, we will get the certificate from the server
		X509 *cert = SSL_get_peer_certificate(ssl);
		if(cert != NULL){
			printf("Certificate confirmed\n");
		}
		else{
			printf("No certificate\n");
		}

		printf("Using TLS we should be set up to communicate\n");

	

		if (!fork()) { // this is the child process
			close(sockfd); // child doesn't need the listener
			printf("==Process Forked==\n");
			int state = 0; //0=default, 1=connected, 2=circle, 3=sphere, 4=cylinder
			char* split;
			if (SSL_write(ssl, "201 HELO RDY", 13) == -1)
				perror("send");
			char username[64];
			char password[64];
			char write[128];
			int flag = 1;
					
			time_t t;
			srand( (unsigned) time(&t));
			while(flag){
				numbytes = SSL_read(ssl, buf, 100);
				printf("recieved: '%s'\n", buf);
				if(strcmp(buf, "AUTH") == 0){

					SSL_write(ssl, "334 dXNlcm5hbWU6", 50);
					SSL_read(ssl, buf, 100);
					printf("recieved: '%s'\n", buf);
					FILE *ifp, *ofp;
					char *mode = "a+";
					ifp = fopen(".user_pass", mode);
					while (fscanf(ifp, "%s %s", username, password) != EOF) {
						
						if(strcmp(buf, username) == 0){
							if (SSL_write(ssl, "334 cGFzc3dvcmQ6", 50) == -1)
								perror("send");
							SSL_read(ssl, buf, 100);
							char tmpbuf[64];
							sprintf(tmpbuf, "NDQ3%s", buf); 
							printf("recieved: '%s'\n", tmpbuf);
							SHA1ToString(tmpbuf, tmpbuf);
							if( strcmp(tmpbuf, password)==0 ){
								flag=0;
								SSL_write(ssl, "PASSWORD CORRECT, WELCOME", 50);
								break;
							}
							else{
								SSL_write(ssl, "INVALID PASSWORD.  RETURN TO AUTH STEP.", 50);
								flag=2;
							}
						}
					  
					}
					if(flag == 1){
						int r = rand();
						r=(r%99999);
						sprintf(write, "330 %d reconnect with AUTH again", r);
						SSL_write(ssl, write, 36);
						sprintf(password, "447%d", r);
						BIO *bmem, *b64;
						BUF_MEM *bptr;
						b64 = BIO_new(BIO_f_base64());
						bmem = BIO_new(BIO_s_mem());
						b64 = BIO_push(b64, bmem);
						BIO_write(b64, password, strlen(password));
						BIO_flush(b64);
						BIO_get_mem_ptr(b64, &bptr);
						char *buff = (char *)malloc(bptr->length);
						memcpy(buff, bptr->data, bptr->length-1);
						buff[bptr->length-1] = 0;
						BIO_free_all(b64);
						SHA1ToString(buff, buff);
						sprintf(write, "%s %s\n",buf, buff);
						
						printf("We will append '%s' to user_pass\n", write);
						fprintf(ifp, write);
					}
					if(flag==2) flag=1;
					fclose(ifp);


					
				}
				else{
					if (SSL_write(ssl, "499 INAVLID FIRST COMMAND", 50) == -1)
						perror("send");
				}
			}

			while(1){
				numbytes = SSL_read(ssl, buf, 100);

				buf[numbytes] = '\0';
				printf("server: received %s", buf);
		
				split= strtok(buf, " "); //first token


				if(split[0]!=0){
					if(  strcmp(split, "HELP") == 0)
					{
						if (SSL_write(ssl, "200 Select shape (CIRCLE, SPHERE, OR CYLINDER) and enter command (AREA, CIRC, VOL, RAD, HGT).", 99) == -1)
							perror("send");
					}
					else if(  strcmp(split, "BYE") == 0)
					{
						if (SSL_write(ssl, "200 BYE", 10) == -1)
							perror("send");
						flag = 0;
					}	
					else if(  strcmp(split, "CIRCLE") == 0)
					{
						if (SSL_write(ssl, "210 CIRCLE ready", 10) == -1)
							perror("send");
						state = 2;
					}
					else if(  strcmp(split, "SPHERE") == 0)
					{
						if (SSL_write(ssl, "220 SPHERE ready", 10) == -1)
							perror("send");
						state = 3;
					}
					else if(  strcmp(split, "CYLINDER") == 0)
					{
						if (SSL_write(ssl, "230 CYLINDER ready", 12) == -1)
							perror("send");
						state = 4;
					}
					else if(  strcmp(split, "AREA") == 0 )
					{
						if(state == 2){

							char* s2 = strtok(NULL, " ");

							if(atoi(s2) == 0){
								if (SSL_write(ssl, "501-Error in args, values must be nonzero", 40) == -1)
									perror("send");
							}
							else
							{
								sprintf(split, "250-Circle, %f", atof(s2)*atof(s2) * 3.1415);
								if (SSL_write(ssl, split, 40) == -1)
									perror("send");
							}
						}
						else if(state == 4){
							char* s2 = strtok(NULL, " ");
							char* s3 = strtok(NULL, " ");
							printf(":%f:", atof(s2));
							if(atoi(s2) == 0 || atoi(s3) == 0){
								if (SSL_write(ssl, "501-Error in args, values must be nonzero", 40) == -1)
									perror("send");
							}
							else
							{
								sprintf(split, "250-Cylinder %f (%f)",(atof(s2)*6.283*atof(s3) + 6.283*atof(s2)*atof(s2)),atof(s3) );
									if (SSL_write(ssl, split, 40) == -1)
										perror("send");
							}
						}
						else
						{
							sprintf(split, "503-Out of Order");
								if (SSL_write(ssl, split, 40) == -1)
									perror("send");
						}
					}
					else if(  strcmp(split, "CIRC") == 0 )
					{
						if(state == 2){
							char* s2 = strtok(NULL, " ");
							if(atoi(s2) == 0){
								if (SSL_write(ssl, "501-Error in args, values must be nonzero", 40) == -1)
									perror("send");
							}
							else{
								sprintf(split, "250-Circle's Circumference %f", (sqrt(atof(s2)/3.1415) * 4/3 ) );
								if (SSL_write(ssl, split, 40) == -1)
									perror("send");
							}
						}

						else{
							sprintf(split, "503-Out of Order");
							if (SSL_write(ssl, split, 40) == -1)
								perror("send");
						}
					}
					else if(  strcmp(split, "VOL") == 0 )
					{
						if(state == 3){
							char* s2 = strtok(NULL, " ");
							if(atoi(s2) == 0){
								if (SSL_write(ssl, "501-Error in args, values must be nonzero", 40) == -1)
									perror("send");
							}
							else
							{  
								sprintf(split, "250-Sphere's Volume %f", (4/3 * 3.1415 * atof(s2) * atof(s2) * atof(s2)));
								if (SSL_write(ssl, split, 40) == -1)
									perror("send");
							}
						}

						else{
							sprintf(split, "503-Out of Order");
								if (SSL_write(ssl, split, 40) == -1)
									perror("send");
						}
					}
					else if(  strcmp(split, "RAD") == 0 )
					{
						if(state == 3){
							char* s2 = strtok(NULL, " ");
				
							if(atoi(s2) == 0){
								if (SSL_write(ssl, "501-Error in args, values must be nonzero", 40) == -1)
									perror("send");
							}
							else
							{  
								sprintf(split, "250-Sphere's Radius %f", (1/2 * sqrt(atof(s2) / 3.1415) ));
								if (SSL_write(ssl, split, 40) == -1)
									perror("send");
							}
						}

						else
						{
							sprintf(split, "503-Out of Order");
							if (SSL_write(ssl, split, 40) == -1)
							perror("send");
						}
					}
					else if(  strcmp(split, "HGT") == 0 )
					{
						if(state == 4){
							char* s2 = strtok(NULL, " ");
							char* s3 = strtok(NULL, " ");
							if(atoi(s2) == 0 || atoi(s3) == 0){
								if (SSL_write(ssl, "501-Error in args, values must be nonzero", 40) == -1)
									perror("send");
							}
							else
							{  
								sprintf(split, "250-Cylinder's Height %f", (atof(s2) / (atof(s3) * atof(s3) * 3.1415)));
								if (SSL_write(ssl, split, 40) == -1)
									perror("send");
							}
						}

						else{
							sprintf(split, "503-Out of Order");
								if (SSL_write(ssl, split, 40) == -1)
									perror("send");
						}
					}
					else if(strcmp(split, "AUTH") == 0){
						if (SSL_write(ssl, "200 - Already Authenticated", 50) == -1)
							perror("send");

					}
					else
					{
						if (SSL_write(ssl, "500 - Unrecognized Command or missing args", 50) == -1)
							perror("send");
					}//end else
				}//end if-else-if-else
			}//end child while
		}//end fork


	} //end accept while

	close(new_fd);  // parent doesn't need this
	printf("closing parent\n");
	

	return 0;
}//end main
