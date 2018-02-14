/*
** client.c -- a stream socket client demo
*/

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

#define SERVER "127.0.0.1"
#define BUFLEN 512  //Max length of buffer
#define PORT 9000   //The port on which to send data
#define MAXDATASIZE 100 // max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
    int sockfd, numbytes;  
    char buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];


    
    char input[16];
    int flag = 1;





   
 
    // first we will create the UDP socket and stuff

    struct sockaddr_in theirUDPSocket;
    int sock, isock, slen=sizeof(theirUDPSocket);
    if ( (sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        perror(s);
        exit(1);
    }
    memset((char *) &theirUDPSocket, 0, sizeof(theirUDPSocket));
    theirUDPSocket.sin_family = AF_INET;
    theirUDPSocket.sin_port = htons(PORT);
    if (inet_aton(SERVER , &theirUDPSocket.sin_addr) == 0) 
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }


         
   char *isudp;
   // then we get the user's first command and attempt to communicate with the server


    printf("hey, do you want this to be UDP?\n");
    fgets(isudp,3,stdin);
    while(atoi(isudp))
    {
	// while we have not terminated connection
        printf("aight now give a command\n");
	fgets(input, 16, stdin);
	for(int i = 0; i < 16; i++){
		if(input[i] == '\n'){
			input[i] = ' ';
			input[i+1] = '\n';
			input[i+2] = '\0';
			i = 16;
			break;
		}
	}

	printf("I'm going to try to send it now\n");
        if (sendto(sock, input, strlen(input) , 0 , (struct sockaddr *) &theirUDPSocket, slen)==-1)
        {
             perror(s);
             exit(1);
        }

	printf("thing sent\n");

        memset(buf,'\0', 80);
        //try to receive some data, this is a blocking call
        if (recvfrom(sock, buf, 80, 0, (struct sockaddr *) &theirUDPSocket, &slen) == -1)
        {
        	perror(s);
        	exit(1);
        }

	printf("thing allegedly got\n");
    //    buf[numbytes] = '\0';
        printf("client: received '%s'\n",buf);

	if(strcmp(buf, "200 BYE")==0){
		printf("Exiting, with GRACE");
		flag=0;
	}

    }


    // if we don't connect to the UDP port (because we were passed a TCP port or a different port)







    // then we will go on and try to connect to the TCP port like I already did.

    if (argc != 3) {
        fprintf(stderr,"usage: client <hostname> <port>\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

    if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        exit(1);
    }
    buf[numbytes] = '\0';
    printf("client: received '%s'\n",buf);



    printf("now I'm serial\n");

    while(flag)
    {
	// while we have not terminated connection

	fgets(input, 16, stdin);
	for(int i = 0; i < 16; i++){
		if(input[i] == '\n'){
			input[i] = ' ';
			input[i+1] = '\n';
			input[i+2] = '\0';
			i = 16;
			break;
		}
	}

	if (send(sockfd, input, 16 , 0) == -1)
	        perror("send");

        if ((numbytes = recv(sockfd, buf, 100, 0)) == -1) {
            perror("recv");
	    printf("o no exiting");
        }

        buf[numbytes] = '\0';
        printf("client: received '%s'\n",buf);

	if(strcmp(buf, "200 BYE")==0){
		printf("Exiting, with GRACE");
		flag=0;
	}

    }

    close(sockfd);

    return 0;
}
