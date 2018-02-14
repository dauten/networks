/**
* Author:  Dale Auten
* Modified: 2/14/18
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


#define BACKLOG 10     // how many pending connections queue will hold

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
	if(argc != 3){
		printf("usage: server <tcp port> <udp port>\n");
		exit(0);
	}
	char *tcpPort = args[1];
	char *udpPort = args[2];

	//this branch of the program handle UDP requests while the parent will go on to handle TCP
	if(!fork()){
		struct sockaddr_in myUDPSocket, theirUDPSocket;
		int sock= sizeof(theirUDPSocket);
		uint slen = sizeof(theirUDPSocket);
		char buf[80];
		//create a UDP socket
		if ((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		{
		perror(s);
		}
		memset((char *) &myUDPSocket, 0, sizeof(myUDPSocket));
		myUDPSocket.sin_family = AF_INET;
		myUDPSocket.sin_port = htons(atoi(udpPort));
		myUDPSocket.sin_addr.s_addr = htonl(INADDR_ANY);
		//bind socket to port
		if( bind(sock, (struct sockaddr*)&myUDPSocket, sizeof(myUDPSocket) ) == -1)
		{
		perror(s);
		}
		int state = 0; //0=default, 1=connected, 2=circle, 3=sphere, 4=cylinder

		//listen for udp input and respond; forever (or until the program is force quit)
		while(1){
			// listen to our port and then process what we hear by tokenizing it
			numbytes = recvfrom(sock, buf, 100, 0,(struct sockaddr *) &theirUDPSocket, &slen);
			if(numbytes == -1 || numbytes == 0){
				perror("recv");
				exit(1);
			}
			buf[numbytes] = '\0';
			printf("server: received %s", buf);
			char* split= strtok(buf, " "); //first token

			//check first word of out input.  determine neccessary behavior, if any, and check for 2nd or 3rd words (args) to compute.
			//this is just a big tedious if statement so its not neccessary to comment it.  its self documenting
			if(split[0]!=0){
				if(  strcmp(split, "HELP") == 0)
				{
					if (sendto(sock, "200 Select shape (CIRCLE, SPHERE, OR CYLINDER) and enter command (AREA, CIRC, VOL, RAD, HGT).", 99  , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
					perror("send");
				}
				else if(  strcmp(split, "BYE") == 0)
				{
					if (sendto(sock, "200 BYE", 10 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
					perror("send");
				}	
				else if(  strcmp(split, "CIRCLE") == 0)
				{
					if (sendto(sock, "210 CIRCLE ready", 10 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
					perror("send");
					state = 2;
				}
				else if(  strcmp(split, "SPHERE") == 0)
				{
					if (sendto(sock, "220 SPHERE ready", 10 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
						perror("send");
					state = 3;
				}
				else if(  strcmp(split, "CYLINDER") == 0)
				{
					if (sendto(sock, "230 CYLINDER ready", 12 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
						perror("send");
					state = 4;
				}
				else if(  strcmp(split, "AREA") == 0 )
				{
					if(state == 2)
					{

						char* s2 = strtok(NULL, " ");

						if(atoi(s2) == 0)
						{
							if (sendto(sock, "501-Error in args, values must be nonzero", 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");
						}
						else{
							sprintf(split, "250-Circle, %f", atof(s2)*atof(s2) * 3.1415);
							if (sendto(sock, split, 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");
						}
					}
					else if(state == 4)
					{
						char* s2 = strtok(NULL, " ");
						char* s3 = strtok(NULL, " ");
						printf(":%f:", atof(s2));
						if(atoi(s2) == 0 || atoi(s3) == 0){
							if (sendto(sock, "501-Error in args, values must be nonzero", 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");
						}else{
							sprintf(split, "250-Cylinder %f (%f)",(atof(s2)*6.283*atof(s3) + 6.283*atof(s2)*atof(s2)),atof(s3) );
							if (sendto(sock, split, 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");
						}
					}
					else
					{
						sprintf(split, "503-Out of Order");
						if (sendto(sock, split, 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
							perror("send");
					}
				}
				else if(  strcmp(split, "CIRC") == 0 )
				{
					if(state == 2)
					{
						char* s2 = strtok(NULL, " ");
						if(atoi(s2) == 0)
						{
							if (sendto(sock, "501-Error in args, values must be nonzero", 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");
						}
						else
						{
							sprintf(split, "250-Circle's Circumference %f", (sqrt(atof(s2)/3.1415) * 4/3 ) );
							if (sendto(sock, split, 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");
						}
					}

					else
					{
						sprintf(split, "503-Out of Order");
						if (sendto(sock, split, 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
							perror("send");
					}
				}
				else if(  strcmp(split, "VOL") == 0 )
				{
					if(state == 3)
					{
						char* s2 = strtok(NULL, " ");
							if(atoi(s2) == 0)
							{
								if (sendto(sock, "501-Error in args, values must be nonzero", 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
									perror("send");
								}
								else
								{  
									sprintf(split, "250-Sphere's Volume %f", (4/3 * 3.1415 * atof(s2) * atof(s2) * atof(s2)));
									if (sendto(sock, split, 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
										perror("send");
								}
							}

					else
					{
						sprintf(split, "503-Out of Order");
						if (sendto(sock, split, 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
							perror("send");
					}
				}
				else if(  strcmp(split, "RAD") == 0 )
				{
					if(state == 3){
						char* s2 = strtok(NULL, " ");

						if(atoi(s2) == 0){
							if (sendto(sock, "501-Error in args, values must be nonzero", 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");
						}
						else
						{  
							sprintf(split, "250-Sphere's Radius %f", (1/2 * sqrt(atof(s2) / 3.1415) ));
							if (sendto(sock, split, 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");
						}
					}

					else{
						sprintf(split, "503-Out of Order");
						if (sendto(sock, split, 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
							perror("send");
					}
				}
				else if(  strcmp(split, "HGT") == 0 )
				{
					if(state == 4){
						char* s2 = strtok(NULL, " ");
						char* s3 = strtok(NULL, " ");
						if(atoi(s2) == 0 || atoi(s3) == 0){
							if (sendto(sock, "501-Error in args, values must be nonzero", 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");
						}
						else
						{
  
							sprintf(split, "250-Cylinder's Height %f", (atof(s2) / (atof(s3) * atof(s3) * 3.1415)));
							if (sendto(sock, split, 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");
						}
					}

					else{
						sprintf(split, "503-Out of Order");
						if (sendto(sock, split, 40 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
							perror("send");
						}
				}
				else if(strcmp(split, "HELO") == 0){
					if (sendto(sock, "200 HELO", 50 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
						perror("send");

				}
				else
				{
					if (sendto(sock, "500 - Unrecognized Command or missing args", 50 , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
						perror("send");
				}//end big tedious if/else

			}

		}//end while
	}//end fork

	//back to the parent, we moce on to preparing TCP side (as per beej's guide)
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

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}
	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		exit(1);
	}
	while(1) 
	{  // main accept() loop

		printf("main loop entered\n\n");
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			continue;
		}
		inet_ntop(their_addr.ss_family,
		get_in_addr((struct sockaddr *)&their_addr),s, sizeof s);
		printf("server: got connection from %s\n", s);

		if (!fork()) { // this is the child process
			close(sockfd); // child doesn't need the listener
			if (send(new_fd, "200 HELO", 13, 0) == -1)
				perror("send");

			int state = 0; //0=default, 1=connected, 2=circle, 3=sphere, 4=cylinder
			char buf[100];
			int flag = 1;
			while(flag){

			numbytes = recv(new_fd, buf, 100, 0);
			if(numbytes == -1 || numbytes == 0){
				perror("recv");
				exit(1);
			}
			buf[numbytes] = '\0';
			printf("server: received %s", buf);
	
			char* split= strtok(buf, " "); //first token


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
			else if(strcmp(split, "HELO") == 0){
				if (send(sockfd, "200 HELO", 50 , 0) == -1)
					perror("send");

			}
			else
			{
				if (send(new_fd, "500 - Unrecognized Command or missing args", 50 , 0) == -1)
					perror("send");
			}//end if-elseif-else

		}//end fork

	}//end while


	close(new_fd);
	exit(0);

	}

	close(new_fd);  // parent doesn't need this
	}

	return 0;
}//end main
