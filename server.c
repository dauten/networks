/**
* Author:  Dale Auten
* Modified: 4/24/18
* Desc: Server Side half of a project to communicate through sockets bound to ports on a linux machine.
* 	It uses TLS for secure communications.  All usernames and passwords are encoded in base64 and
*	passwords are also salted and hashed using SHA1 for additional security in storage
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

	unsigned char hash[SHA_DIGEST_LENGTH];
	
	SHA1(str, strlen(str), hash);	//apply SHA to input string storing digest in buffer
	sprintf(targ, "");		//instantiate empty string array
	for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
		//iterate through ther digest translating it from hex to the corresponding ASCII in our destination
		sprintf(targ, "%s%02x", targ, hash[i]);
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

	//after this point socket is set up, now we will go and give it to SSL.
	//SSL setup adapted from http://simplestcodings.blogspot.com/2010/08/secure-server-client-using-openssl-in-c.html

	
	//first call the setup functions and use TLSv1.2, checking to see it setup correctly
	SSL_CTX *context;
	SSL_library_init();

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	if((context=SSL_CTX_new(TLSv1_2_server_method()))==NULL) printf("context may not have been setup correctly\n");

	//load our certificate and private key and check that they loaded.
	//note we keep going even if there's an error, so if there's an error things will break later
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

		//accept incoming connections as usual into new_fd
		printf("main loop entered\n\n");
		sin_size = sizeof their_addr;
		SSL *ssl;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			continue;
		}

		char buf[100];

		//print incoming IP
		inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),s, sizeof s);
		printf("server: got connection from %s\n", s);

		//load up our SSL connection using our context and the incoming socket
		ssl = SSL_new(context);
		SSL_set_fd(ssl, new_fd);
		
		//accept the connection using SSL and pray there was no error		
		if(SSL_accept(ssl) < 0) printf("We had some trouble accepting that client over SSL\n");
		// to double check, we will get the certificate from the server
		X509 *cert = SSL_get_peer_certificate(ssl);
		if(cert != NULL){
			printf("Certificate confirmed\n");
		}
		else{
			printf("No certificate\n");
		}

		//split this connection off to a different process
		if (!fork()) {
			close(sockfd); // child doesn't need the listener
			printf("==Process Forked==\n");
			// load up some of our variables and write weolcome command			
			int state = 0; //0=default, 1=connected, 2=circle, 3=sphere, 4=cylinder
			char* split;
			if (SSL_write(ssl, "201 AUTH RDY", 13) == -1)
				perror("send");
			char username[64];
			char password[64];
			char write[128];
			int flag = 1;

			//each process has its own random function based of its rough time of creation
			//so there are fewer collisions when we generate passwords					
			time_t t;
			srand( (unsigned) time(&t));

			//this first loop is the "login" loop.  It will expeect login commands
			//and will exit when it logs in properly
			while(flag){
				//read input from clients, print it, and see if its AUTH (as it is needed to login)
				SSL_read(ssl, buf, 100);
				printf("recieved: '%s'\n", buf);
				if(strcmp(buf, "AUTH") == 0){

					//if so, reply and expect username.
					SSL_write(ssl, "334 dXNlcm5hbWU6", 50);
					SSL_read(ssl, buf, 100);
					printf("recieved: '%s'\n", buf);
					
					//open a file in append mode
					FILE *ifp;
					char *mode = "a+";
					ifp = fopen(".user_pass", mode);
					
					//iterate through every user in file, getting the 2 parts
					while (fscanf(ifp, "%s %s", username, password) != EOF) {
						
						//check first part.  if wrong, advance loop/check next if it exists
						if(strcmp(buf, username) == 0){
							//if right, request password and await input
							if (SSL_write(ssl, "334 cGFzc3dvcmQ6", 50) == -1)
								perror("send");
							SSL_read(ssl, buf, 100);
							printf("recieved: '%s'\n", buf);

							//we resalt the input by adding 447 in base64 to beginning
							char tmpbuf[64];
							sprintf(tmpbuf, "NDQ3%s", buf); 

							//hash to make it even more secure for storage.  then compare and allow or deny
							SHA1ToString(tmpbuf, tmpbuf);
							if( strcmp(tmpbuf, password)==0 ){
								flag=0;	//set flag so we exit loop
								SSL_write(ssl, "PASSWORD CORRECT, WELCOME", 50);
								break;
							}
							else{
								SSL_write(ssl, "INVALID PASSWORD.  RETURN TO AUTH STEP.", 50);
								flag=2;	//set flag that user exits, login failed.
							}
						}
					  
					}
					if(flag == 1){
						//this will be entered iff the username tried does not exist.
						//make a random password and give it to the user
						int r = rand();
						r=(r%99999);
						sprintf(write, "330 %d reconnect with AUTH again", r);
						SSL_write(ssl, write, 36);
						//salt password and base64 encode it.
						sprintf(password, "447%d", r);
						//since openssl has a way to do this we'll use that.
						//modifed from http://www.ioncannon.net/programming/122/howto-base64-decode-with-cc-and-openssl/
						//create our BIOs and push the memory through
						BIO *bmem, *b64;
						BUF_MEM *bptr;
						b64 = BIO_new(BIO_f_base64());
						bmem = BIO_new(BIO_s_mem());
						b64 = BIO_push(b64, bmem);
						//push our password through the BIO function that gets
						//pushed through bmemory
						BIO_write(b64, password, strlen(password));
						BIO_flush(b64);
						BIO_get_mem_ptr(b64, &bptr);
						//get the now enccoded data and pull to a temp variable
						char *buff = (char *)malloc(bptr->length);
						memcpy(buff, bptr->data, bptr->length-1);
						buff[bptr->length-1] = 0;
						BIO_free_all(b64);
						//one last thing, before we store it we hash it
						SHA1ToString(buff, buff);

						//finally format the line, print to console for posterity, and add to file
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
			//once login is successful/that while loop is exited, we enter the main/command while loop
			while(1){

				//read and tokenize our input
				numbytes = SSL_read(ssl, buf, 100);

				buf[numbytes] = '\0';
				printf("server: received %s", buf);
		
				split= strtok(buf, " "); //first token

				//look at command part, determine command, then perform appropriate task based off
				//values passed (ie whether to calculate or throw and error) and current state (if in right mode).
				//basic process is, look at first token to see what command to do, check current state if its a command
				//that needs that, make sure there are enough args and throw an error if that or state is off,
				//do math if needed and reply to client with result.
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
						if (SSL_write(ssl, "210 CIRCLE ready", 20) == -1)
							perror("send");
						state = 2;
					}
					else if(  strcmp(split, "SPHERE") == 0)
					{
						if (SSL_write(ssl, "220 SPHERE ready", 20) == -1)
							perror("send");
						state = 3;
					}
					else if(  strcmp(split, "CYLINDER") == 0)
					{
						if (SSL_write(ssl, "230 CYLINDER ready", 20) == -1)
							perror("send");
						state = 4;
					}
					else if(  strcmp(split, "AREA") == 0 )
					{
						if(state == 2){
							char* s2 = strtok(NULL, " ");
							printf("s2 is %s, as a number %d\n", s2,s2);
							if(s2 == 0 || atoi(s2) == 0){
								if (SSL_write(ssl, "501-Error in args, values must be nonzero", 64) == -1)
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
							if(!s2 || !s3 || atoi(s2) == 0 || atoi(s3) == 0){
								if (SSL_write(ssl, "501-Error in args, values must be nonzero", 64) == -1)
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
							if(!s2 || atoi(s2) == 0){
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
							if(!s2 || atoi(s2) == 0){
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
							
							if(!s2 || atoi(s2) == 0){
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
							if(!s2 || !s3 || atoi(s2) == 0 || atoi(s3) == 0){
								if (SSL_write(ssl, "501-Error in args, values must be nonzero", 64) == -1)
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
						if (SSL_write(ssl, "500 - Unrecognized Command or missing args", 80) == -1)
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
