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

	//declaration
	struct sockaddr_in otherUDP;
	int udpSock =sizeof(otherUDP);
	uint slen=sizeof(otherUDP);
	char in[100];


	//prompt for input even though we don't use this until a little later
	printf("Please attempt to connect to the server with 'HELO <hostname>'\n");
	fgets(input, 64, stdin);

	//setting up udp socket
	udpSock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	memset((char *) &otherUDP, 0, sizeof(otherUDP));
	otherUDP.sin_family = AF_INET;
	otherUDP.sin_port = htons(PORT);
	if (inet_aton(SERVER , &otherUDP.sin_addr) == 0) 
	{
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}
	sendto(udpSock, input, 64 , 0 , (struct sockaddr *) &otherUDP, slen);
	memset(in,'\0', 100);

	//declaration for timeout.  modified from linux man pages (https://linux.die.net/man/2/select)
	fd_set readfds;
	int n;
	struct timeval tv;
	FD_ZERO(&readfds);
	FD_SET(udpSock,&readfds);
	n=udpSock+1;
	tv.tv_sec=0;
	tv.tv_usec = 1000000;

	//we essentially ping the port we were giving using UDP. if the server responds in
	//UDP then this is a unreliable connection and we stay in the main of the 'if'
	int rvr = select(n, &readfds, NULL, NULL, &tv);
	if( rvr!=0 ){
		if ((numbytes = recvfrom(udpSock, buf, 100, 0 , (struct sockaddr *) &otherUDP, &slen)) == -1) {
			perror("recv");
		}
		printf("client: received '%s'\n",buf);
		int flag = 1;
		
		//start command-input loop
		while(flag)
		{
			//get and reformat input
			fgets(input, 64, stdin);
			for(int i = 0; i < 64; i++){
				if(input[i] == '\n'){
					input[i] = ' ';
					input[i+1] = '\n';
					input[i+2] = '\0';
					i = 64;
					break;
				}
			}//end for

			//send message...
			if (sendto(udpSock, input, 64 , 0 , (struct sockaddr *) &otherUDP, slen) == -1)
				perror("send");

			//...recieve input...
			if ((numbytes = recvfrom(udpSock, buf, 100, 0 , (struct sockaddr *) &otherUDP, &slen)) == -1) {
				perror("recv");
			}

			//...then output
			buf[numbytes] = '\0';
			printf("client: received '%s'\n",buf);

			//...when we get the OK from the server we exit the loop to close socket & exit
			if(strcmp(buf, "200 BYE")==0){
				flag=0;
			}
		}//end while

		close(tcpSock);
		return 0;

	}//end if
	else{
		//this else is entered in connection is NOT UDP (so either it is TCP or we were given a bad port)

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

		//we expect an initial response from the server.
		if ((numbytes = recv(tcpSock, buf, 128-1, 0)) == -1) {
			perror("recv");
			exit(1);
		}
		buf[numbytes] = '\0';

		printf("client: received '%s'\n",buf);

		//TCP command-loop
		while(flag)
		{
			//input
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
			if (send(tcpSock, input, 16 , 0) == -1)
				perror("send");
			if ((numbytes = recv(tcpSock, buf, 100, 0)) == -1) {
				perror("recv");
			}
			buf[numbytes] = '\0';
			printf("client: received '%s'\n",buf);

			if(strcmp(buf, "200 BYE")==0){
				flag=0;
			}
		} //end while

		close(tcpSock);
		return 0;

	}//end else

} //end main
