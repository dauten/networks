/**
* Author:  Dale Auten
* Modified: 3/27/18
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
#include <sys/mman.h>
#include <assert.h>
#include <time.h>

#define BACKLOG 10     // how many pending connections queue will hold

uint nextPort = 0;

//two functions from beej's guide
void sigchld_handler(int s)
{
	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

		errno = saved_errno;
}

char** str_split(char* a_str, const char a_delim);

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

struct message {
	int port;
	char *rec;
	
	char *msg;
};

struct user {
	char *user;
	char *nick;
	char mode;
	int port;
};

struct message queue[100];
struct user users[100];

int main(int argc, char *args[])
{/*
	time_t rawtime;
	struct tm * timeinfo;

	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	char time[6], loc[20];
	strftime(time, 6, "%H%M", timeinfo);
	printf ( "Current local time: %s\n", time);
	mkdir(time);
	sprintf(loc, "%s.txt\0", time);
	chdir(time);

*/
	FILE *fp;
	char file[12];

	//sprintf(file, "%s/f.txt", time);
	//printf("subfolder is %s\n",file);
	fp = fopen("file.txt", "w+");
	fprintf(fp, "This is testing for fprintf...\n");
	fputs("This is testing for fputs...\n", fp);
	fclose(fp);

	//declarations taken from beej's guide
	int sockfd, new_fd, numbytes;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int firstPort;


	//check that the user included arguments then copy them into our ports
	if(argc != 2){
		printf("usage: server <udp port>\n");
		exit(0);
	}

	char *udpPort = args[1];
	nextPort = atoi(args[1]);
	firstPort = nextPort + 1;
	//listen for messages and return an ACK
	struct sockaddr_in myUDPSocket, theirUDPSocket;
	int sock= sizeof(theirUDPSocket);
	uint slen = sizeof(theirUDPSocket);
	char buf[512], old[512];
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


	//listen for udp input and respond; forever (or until the program is force quit)
	//this main loop just looks for port requests then sends client that port.
	while(1){




		// listen to our port and then process what we hear by tokenizing it
		numbytes = recvfrom(sock, buf, 512, 0,(struct sockaddr *) &theirUDPSocket, &slen);
		if(numbytes == -1 || numbytes == 0){
			perror("recv");
			exit(1);
		}
		buf[numbytes] = '\0';
		

		if(  buf[0] == '#' )
		{

			nextPort++;
			if(!fork()){

				//format to text and tell client what port to use
				sprintf(buf, "%d", nextPort);
				if (sendto(sock, buf, 4  , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
					perror("send");

				//child will not need old socket
				close(sock);


				//listen for messages and return an ACK
				struct sockaddr_in myUDPSocket, theirUDPSocket;
				int sock= sizeof(theirUDPSocket);
				uint slen = sizeof(theirUDPSocket);
				char buf[512], old[512];

				//create a new UDP socket
				if ((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
				{
					perror(s);
				}

				memset((char *) &myUDPSocket, 0, sizeof(myUDPSocket));
				myUDPSocket.sin_family = AF_INET;
				myUDPSocket.sin_port = htons(nextPort);
				myUDPSocket.sin_addr.s_addr = htonl(INADDR_ANY);

				//bind socket to port
				if( bind(sock, (struct sockaddr*)&myUDPSocket, sizeof(myUDPSocket) ) == -1)
				{
					perror(s);
				}
				

				//now we have a new socket up, this loop in child proces will listen to its user
				//and process all commands for it.
				while(1){
					//declaration for timeout.  modified from linux man pages (https://linux.die.net/man/2/select)
					fd_set readfds;
					int n;
					struct timeval tv;
					FD_ZERO(&readfds);
					FD_SET(sock,&readfds);
					n=sock+1;
					tv.tv_sec=0;
					tv.tv_usec = 1000000;


					
					select(n, &readfds, NULL, NULL, &tv);

					char **tokens = NULL;					

					if(FD_ISSET(sock, &readfds) ){
						// listen to our port and then process what we hear by tokenizing it
						numbytes = recvfrom(sock, buf, 512, 0,(struct sockaddr *) &theirUDPSocket, &slen);
						if(numbytes == -1 || numbytes == 0){
							perror("recv");
							exit(1);
						}
						buf[numbytes] = '\0';
						if(buf[0] != 0 && buf[0] != '\n'){	//if we received actual input
							printf("\nserver: received %s\ton %f\n", buf, (float)nextPort);
							tokens = str_split(buf, ' ');	//tokenize input string for easier parsing
							if(strcmp(tokens[0], "ME") == 0){
								char out[100];
								struct user temp[100];
								sprintf(out, "USER: %s, NICK: %s, MODE: %c, PORT: %d\n",temp[nextPort-firstPort].user, temp[nextPort-firstPort].nick, temp[nextPort-firstPort].mode,  temp[nextPort-firstPort].port);
								//sprintf(out, "USER: %s, NICK: %s, MODE: %c, PORT: %d\n",temp[0].user, temp[nextPort-firstPort].nick, temp[nextPort-firstPort].mode,  temp[nextPort-firstPort].port);
								
								if (sendto(sock, out, 99, 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
									perror("send");	
							}//end ME
							else if(strcmp(tokens[0], "USER") == 0){
	

							}//end USER
							else if(strcmp(tokens[1], "NICK") == 0){
	

							}//end NICK
							else if(strcmp(tokens[0], "PRIVMSG") == 0){




							}//end PRIVMSG
	

							if (sendto(sock, "@ACK", 99  , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");	
						}


					}
/*
					memcpy(temp, shuserlist, sizeof(shuserlist));
									
					memcpy(queue, shqueue, sizeof(shqueue));
					printf("temp is: %s, %s, %d, also %s\n", queue[0].msg, queue[0].rec, queue[0].port, shmem);
					for (int i = 0; i < 100; i++){
						if(queue[i].rec && temp[nextPort-firstPort].user && strcmp(queue[0].rec, temp[nextPort-firstPort].user) == 0){

							if (sendto(sock, queue[0].msg, 99  , 0,(struct sockaddr *) &theirUDPSocket, slen) == -1)
								perror("send");
							queue[0].rec = "";
							memcpy(shqueue, queue, sizeof(shqueue));

						}
					}*/


					memset(buf, '\0', 512);
					 	

				}
			}
		}
	}

	close(new_fd);
	exit(0);

	return 0;

}//end main

char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}



