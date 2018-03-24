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

#include <pthread.h>

#include <arpa/inet.h>

int ackFlag = 0;

//function from beej's guide
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
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


	//declaration
	int tcpSock, numbytes;  
	char buf[128];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	char *SERVER = argv[1];
	uint PORT = atoi(argv[2]);
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


	pthread_t t1;
	struct args_struct args;
	args.udpSock= udpSock;
	args.otherUDP=otherUDP;
	args.slen=slen;
	
	//start listener and sender threads
	pthread_create(&t1, NULL, &listener, (void *)&args);
	inputParser(udpSock, otherUDP, slen);
	while(1);


} //end main


//thread that listens for input from server and does appropriate thing with it
void *listener(void  *args){
	
	struct args_struct *arg = (struct args_struct *)args;
	int udpSock = arg->udpSock;
	struct sockaddr_in otherUDP = arg->otherUDP;
	uint slen = arg->slen;

	int numbytes;
	char buf[100];
	while(1){
		//recieve input...
		if ((numbytes = recvfrom(udpSock, buf, 100, 0 , (struct sockaddr *) &otherUDP, &slen)) == -1) {
			perror("recv");
		}
		printf("\ngot: %s", buf);
		if(buf[0] == '@')
			ackFlag = 1;

	}

}



//thread that listens for keyboard input then sends it to server
void inputParser(int udpSock, struct sockaddr_in otherUDP, uint slen){

	//this is the parent; the sender
	char input[100];
	while(1){

		//get and reformat input
		printf("\n>");
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

		sendMessage(udpSock, input, otherUDP, slen, 0);
	}
}

/*
* Sends message then awaits ACK.  If we get one within X seconds message was sent, otherwise we will resend a couple times
*/
uint sendMessage(int udpSock, char *input, struct sockaddr_in otherUDP, uint slen, int depth){

	char in[100];
	if(depth > 10){
		printf("Sorry, that message could not be delivered.  Try again later.");
		return 1;	// error return message
	}

	sendto(udpSock, input, 64 , 0 , (struct sockaddr *) &otherUDP, slen);
	memset(in,'\0', 100);

	while(!ackFlag){
		sleep(1)
		//lack of ACK, resend.
		//it is ok if the server DID receive the message and an ACK is on the way,
		//as long as the server receives the message at some point its its job to
		//sort out duplicates, and we should receive the ACK meant for the first msg
		//for the second one we send
		return sendMessage(udpSock, input, otherUDP, slen, in, depth+1);
		//so long as we don't stack overflow or something we should exit the function call eventually so
		
	}
	printf("\nACK received");
	return 0;
	ackFlag = 0;
}
