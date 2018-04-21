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

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "fd.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "fd.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
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




	SSL_CTX *ctx;                                                                                                                          
    SSL_library_init();
 
	/* init */                                                                                                                             
	SSL_load_error_strings();                                                                                                              
	OpenSSL_add_all_algorithms();                                                                                                          

	
	if (!(ctx = SSL_CTX_new(TLSv1_2_server_method() ))) {                                                                                                    
	exit(1);                                                                                                                             
	}

	/* configure context */                                                                                                                
	//  SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the key and cert */                                                                                                             
	if (SSL_CTX_use_certificate_file(ctx, "example.crt", SSL_FILETYPE_PEM) <= 0) {                                                            
	exit(1);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "fd.key", SSL_FILETYPE_PEM) <= 0) {                                                              
	exit(1);
	}                                                                                                                                      

	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
	fprintf(stderr, "Private key does not match the public certificate\n");
	abort();
	}


	while(1) 
	{  // main accept() loop

		printf("main loop entered\n\n");
		sin_size = sizeof their_addr;
		BIO *bio;		
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			continue;
		}

		char buf[100];

		memcpy(buf, "this is sent securely", 64);

		printf("socket formed and connected, negotiating ssl...\n");
		SSL *ssl;			                                                            
		/* create ssl instance from context */                                                                                               
		ssl = SSL_new(ctx);
		if(ssl) printf("ssl made\n");
		/* assign socket to ssl intance */                                                                                                   
		SSL_set_fd(ssl, new_fd);                                                                                                             

                                                                                       
  		  if ( SSL_accept(ssl) == -1 )     /* do SSL-protocol accept */
   		     ERR_print_errors_fp(stderr);                                                                                                                   
		/* perform ssl reads / writes */


		X509 *cert;
		char *line;

		cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
		if ( cert != NULL )
		{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
		}
		else
		printf("No certificates.\n");


		printf("READING FROM SSL: \n");
		SSL_read(ssl, buf, sizeof(buf));

            printf("Client msg: \"%s\"\n", buf);
            SSL_write(ssl, buf, strlen(buf)); 


		/* free ssl instance */
		SSL_free(ssl);



		inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),s, sizeof s);
		printf("server: got connection from %s\n", s);

	

		if (!fork()) { // this is the child process
			close(sockfd); // child doesn't need the listener
			printf("about to enter loop\n");
			int state = 0; //0=default, 1=connected, 2=circle, 3=sphere, 4=cylinder
			char* split;
			if (send(new_fd, "201 HELO RDY", 13, 0) == -1)
				perror("send");
			char username[64];
			char password[64];
			char write[128];
			int flag = 1;
			while(flag){
				numbytes = recv(new_fd, buf, 100, 0);
				printf("recieved: %s\n", buf);
				if(strcmp(buf, "AUTH") == 32){

					send(new_fd, "334 dXNlcm5hbWU6", 50 , 0);
					recv(new_fd, buf, 100, 0);
					printf("recieved: '%s'\n", buf);
					FILE *ifp, *ofp;
					char *mode = "a+";
					ifp = fopen(".user_pass", mode);
					while (fscanf(ifp, "%s %s", username, password) != EOF) {
						
						if(strcmp(buf, username) == 0){
							if (send(new_fd, "334 cGFzc3dvcmQ6", 50 , 0) == -1)
								perror("send");
							recv(new_fd, buf, 100, 0);
							printf("recieved: '%s'\n", buf);
							if( strcmp(buf, password)==0 ){
								flag=0;
								send(new_fd, "PASSWORD CORRECT, WELCOME", 50 , 0);
								break;
							}
							else{
								send(new_fd, "INVALID PASSWORD.  RETURN TO AUTH STEP.", 50 , 0);
								flag=2;
							}
						}
					  
					}
					if(flag == 1){
						int r = rand();
						r=(r%99999);
						sprintf(write, "330 %d reconnect with AUTH again", r);
						send(new_fd, write, 36, 0);
						sprintf(password, "%d", r);
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
						sprintf(write, "%s %s\n",buf, buff);

						printf("We will append '%s' to user_pass\n", write);
						fprintf(ifp, write);
						//next we write that stuff to .user_pass
						//functionality coming later, comrade
					}
					if(flag==2) flag=1;
					fclose(ifp);


					
				}
				else{
					if (send(new_fd, "499 INAVLID FIRST COMMAND", 50 , 0) == -1)
						perror("send");
				}
			}

			while(1){
				numbytes = recv(new_fd, buf, 100, 0);

				buf[numbytes] = '\0';
				printf("server: received %s", buf);
		
				split= strtok(buf, " "); //first token


				if(split[0]!=0){
					if(  strcmp(split, "HELP") == 0)
					{
						if (send(new_fd, "200 Select shape (CIRCLE, SPHERE, OR CYLINDER) and enter command (AREA, CIRC, VOL, RAD, HGT).", 99  , 0) == -1)
							perror("send");
					}
					else if(  strcmp(split, "BYE") == 0)
					{
						if (send(new_fd, "200 BYE", 10 , 0) == -1)
							perror("send");
						flag = 0;
					}	
					else if(  strcmp(split, "CIRCLE") == 0)
					{
						if (send(new_fd, "210 CIRCLE ready", 10 , 0) == -1)
							perror("send");
						state = 2;
					}
					else if(  strcmp(split, "SPHERE") == 0)
					{
						if (send(new_fd, "220 SPHERE ready", 10 , 0) == -1)
							perror("send");
						state = 3;
					}
					else if(  strcmp(split, "CYLINDER") == 0)
					{
						if (send(new_fd, "230 CYLINDER ready", 12 , 0) == -1)
							perror("send");
						state = 4;
					}
					else if(  strcmp(split, "AREA") == 0 )
					{
						if(state == 2){

							char* s2 = strtok(NULL, " ");

							if(atoi(s2) == 0){
								if (send(new_fd, "501-Error in args, values must be nonzero", 40 , 0) == -1)
									perror("send");
							}
							else
							{
								sprintf(split, "250-Circle, %f", atof(s2)*atof(s2) * 3.1415);
								if (send(new_fd, split, 40 , 0) == -1)
									perror("send");
							}
						}
						else if(state == 4){
							char* s2 = strtok(NULL, " ");
							char* s3 = strtok(NULL, " ");
							printf(":%f:", atof(s2));
							if(atoi(s2) == 0 || atoi(s3) == 0){
								if (send(new_fd, "501-Error in args, values must be nonzero", 40 , 0) == -1)
									perror("send");
							}
							else
							{
								sprintf(split, "250-Cylinder %f (%f)",(atof(s2)*6.283*atof(s3) + 6.283*atof(s2)*atof(s2)),atof(s3) );
									if (send(new_fd, split, 40 , 0) == -1)
										perror("send");
							}
						}
						else
						{
							sprintf(split, "503-Out of Order");
								if (send(new_fd, split, 40 , 0) == -1)
									perror("send");
						}
					}
					else if(  strcmp(split, "CIRC") == 0 )
					{
						if(state == 2){
							char* s2 = strtok(NULL, " ");
							if(atoi(s2) == 0){
								if (send(new_fd, "501-Error in args, values must be nonzero", 40 , 0) == -1)
									perror("send");
							}
							else{
								sprintf(split, "250-Circle's Circumference %f", (sqrt(atof(s2)/3.1415) * 4/3 ) );
								if (send(new_fd, split, 40 , 0) == -1)
									perror("send");
							}
						}

						else{
							sprintf(split, "503-Out of Order");
							if (send(new_fd, split, 40 , 0) == -1)
								perror("send");
						}
					}
					else if(  strcmp(split, "VOL") == 0 )
					{
						if(state == 3){
							char* s2 = strtok(NULL, " ");
							if(atoi(s2) == 0){
								if (send(new_fd, "501-Error in args, values must be nonzero", 40 , 0) == -1)
									perror("send");
							}
							else
							{  
								sprintf(split, "250-Sphere's Volume %f", (4/3 * 3.1415 * atof(s2) * atof(s2) * atof(s2)));
								if (send(new_fd, split, 40 , 0) == -1)
									perror("send");
							}
						}

						else{
							sprintf(split, "503-Out of Order");
								if (send(new_fd, split, 40 , 0) == -1)
									perror("send");
						}
					}
					else if(  strcmp(split, "RAD") == 0 )
					{
						if(state == 3){
							char* s2 = strtok(NULL, " ");
				
							if(atoi(s2) == 0){
								if (send(new_fd, "501-Error in args, values must be nonzero", 40 , 0) == -1)
									perror("send");
							}
							else
							{  
								sprintf(split, "250-Sphere's Radius %f", (1/2 * sqrt(atof(s2) / 3.1415) ));
								if (send(new_fd, split, 40 , 0) == -1)
									perror("send");
							}
						}

						else
						{
							sprintf(split, "503-Out of Order");
							if (send(new_fd, split, 40 , 0) == -1)
							perror("send");
						}
					}
					else if(  strcmp(split, "HGT") == 0 )
					{
						if(state == 4){
							char* s2 = strtok(NULL, " ");
							char* s3 = strtok(NULL, " ");
							if(atoi(s2) == 0 || atoi(s3) == 0){
								if (send(new_fd, "501-Error in args, values must be nonzero", 40 , 0) == -1)
									perror("send");
							}
							else
							{  
								sprintf(split, "250-Cylinder's Height %f", (atof(s2) / (atof(s3) * atof(s3) * 3.1415)));
								if (send(new_fd, split, 40 , 0) == -1)
									perror("send");
							}
						}

						else{
							sprintf(split, "503-Out of Order");
								if (send(new_fd, split, 40 , 0) == -1)
									perror("send");
						}
					}
					else if(strcmp(split, "AUTH") == 0){
						if (send(new_fd, "200 - Already Authenticated", 50 , 0) == -1)
							perror("send");

					}
					else
					{
						if (send(new_fd, "500 - Unrecognized Command or missing args", 50 , 0) == -1)
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
