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


	//listen for messages and return an ACK
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

		if(  strcmp(split, "HELP") == 0)
		{
			if (sendto(sock, "@ACK: This is the only command lol", 99  , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
			perror("send");
		}
		else{
			if (sendto(sock, "@ACK: Invalid Command", 99  , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
			perror("send");
		}

	}


	close(new_fd);
	exit(0);



	return 0;
}//end main
