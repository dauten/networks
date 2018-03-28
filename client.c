/**
* Author:  Dale Auten
* Modified: 3/27/18
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

uint running = 1;

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
	// check if user gave needed args
	if (argc != 3) {
		fprintf(stderr,"usage: client <hostname> <port>\n");
		exit(1);
	}

	char user[10];
	printf("please enter username");
//	fgets(user, 10, stdin);
	char nick[10];
	printf("please enter nickname");
//	fgets(nick, 10, stdin);	

	//declaration
	int udpSock, numbytes;  
	char buf[512];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	char *SERVER = argv[1];
	uint PORT = atoi(argv[2]);
	int flag = 1;

	//declaration
	struct sockaddr_in otherUDP;
	uint slen=sizeof(otherUDP);

	if (inet_aton(SERVER , &otherUDP.sin_addr) == 0) 
	{
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}

	//setting up udp socket
	udpSock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	memset((char *) &otherUDP, 0, sizeof(otherUDP));
	otherUDP.sin_family = AF_INET;
	otherUDP.sin_port = htons(PORT);	

	//send our request for a port
	sendto(udpSock, "#", 2 , 0 , (struct sockaddr *) &otherUDP, slen);
	//get the response	
	if ((numbytes = recvfrom(udpSock, buf, 512, 0 , (struct sockaddr *) &otherUDP, &slen)) == -1)
		perror("recv");
	PORT = atoi(buf);
	printf("\nwe got port %d", PORT);


	// we will now close the old datagram and re-establish connection using the port given by the server
	close(udpSock);

	//declaration
	slen=sizeof(otherUDP);

	if (inet_aton(SERVER , &otherUDP.sin_addr) == 0) 
	{
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}

	//setting up udp socket
	udpSock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	memset((char *) &otherUDP, 0, sizeof(otherUDP));
	otherUDP.sin_family = AF_INET;
	otherUDP.sin_port = htons(PORT);

	udpSock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	memset((char *) &otherUDP, 0, sizeof(otherUDP));
	otherUDP.sin_family = AF_INET;
	otherUDP.sin_port = htons(PORT);	

	// then, we merely listen for any input and output
	pthread_t t1;
	struct args_struct args;
	args.udpSock= udpSock;
	args.otherUDP=otherUDP;
	args.slen=slen;
	
	//start listener and sender threads
	pthread_create(&t1, NULL, &listener, (void *)&args); //as far as I'm aware you can only pass one 'arg' to pthread
							     //so to get all 3 things we need we make a single struct w/ them all
	inputParser(udpSock, otherUDP, slen);
	while(running);
	exit(0);


} //end main

//thread that listens for input from server and does appropriate thing with it
void *listener(void  *args){
	
	struct args_struct *arg = (struct args_struct *)args;
	int udpSock = arg->udpSock;
	struct sockaddr_in otherUDP = arg->otherUDP;
	uint slen = arg->slen;

	int numbytes;
	char buf[512];
	while(running){
		//recieve input...
		if ((numbytes = recvfrom(udpSock, buf, 512, 0 , (struct sockaddr *) &otherUDP, &slen)) == -1) {
			perror("recv");
		}
		//print any input we recieve.  this is indiscriminate atm but will do some formatting later
		printf("\ngot: %s", buf);
		//if the message was an ACK we set a flag so the sender knows it was
		if(buf[0] == '@')
			ackFlag = 1;
		//else if etc

	}

}

//thread that listens for keyboard input then sends it to server
void inputParser(int udpSock, struct sockaddr_in otherUDP, uint slen){

	//this is the parent; the sender
	char input[512];
	while(running){

		//get and reformat input
		printf("\n\t>");
		fgets(input, 512, stdin);
		for(int i = 0; i < 510; i++){
			if(input[i] == '\n'){
				input[i] = ' ';
				input[i+1] = '\n';
				input[i+2] = '\0';
				i = 512;
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

	if(depth > 10){
		printf("Sorry, that message could not be delivered.  Try again later.");
		return 1;	// error return message
	}

	sendto(udpSock, input, 512 , 0 , (struct sockaddr *) &otherUDP, slen);
	memset(input,'\0', 512);

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

	ackFlag = 0;
	return 0;


}
