/*
    Simple udp client
*/
#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include<arpa/inet.h>
#include<sys/socket.h>
 
#define SERVER "127.0.0.1"
#define BUFLEN 512  //Max length of buffer
#define PORT 8888   //The port on which to send data
 
void die(char *s)
{
    perror(s);
    exit(1);
}
 
int main(void)
{
    struct sockaddr_in theirUDPSocket;
    int sock, isock, slen=sizeof(theirUDPSocket);
    if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
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
    while(1)
    {
        printf("Enter message : ");
        gets(message);
         
        //send the message
        if (sendto(s, message, strlen(message) , 0 , (struct sockaddr *) &theirUDPSocket, slen)==-1)
        {
   	     perror(s);
             exit(1);
        }
         
        //receive a reply and print it
        //clear the buffer by filling null, it might have previously received data
        memset(buf,'\0', BUFLEN);
        //try to receive some data, this is a blocking call
        if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &theirUDPSocket, &slen) == -1)
        {
            die("recvfrom()");
        }
         
        puts(buf);
    }
 
    close(s);
    return 0;
}
