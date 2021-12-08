#include <stdio.h>       // printf()
#include <stdlib.h>
#include <unistd.h>      // write()
#include <string.h>
#include <sys/socket.h>  // sockaddr_in
#include <arpa/inet.h>
#include <netdb.h>
#define PORT 53

void func(int new_socket)
{
   char hostname[100] , ip_address[100];
   struct hostent *he;
   struct in_addr **addr_list;

   recv(new_socket,hostname,sizeof(hostname),0);

   if( (he = gethostbyname(hostname)) == NULL )
   {
      // get host by name failed
      herror("gethostbyname");
   }

   addr_list = (struct in_addr **) he->h_addr_list;

   for(int i = 0;addr_list[i] != NULL; i++)
   {
      // return the first one
      strcpy(ip_address,inet_ntoa(*addr_list[i]) );
   }

   send(new_socket,ip_address,sizeof(ip_address),0);
}

int main(int argc, char *argv[])
{
   int socket_desc, new_socket, c;
   struct sockaddr_in server , client;

   // socket creation and verification
   socket_desc = socket(AF_INET,SOCK_STREAM,0);
   if(socket_desc == -1)
   {
      printf("socket creation failed :(\n");
      exit(-1);
   }
   else
      printf("Socket successfully created...\n");

   // assigning IP address and PORT
   server.sin_family = AF_INET;
   server.sin_addr.s_addr = INADDR_ANY;
   server.sin_port = htons(PORT);

   // binding newly created socket to given IP and verification
   if( bind(socket_desc,(struct sockaddr *)&server,sizeof(server)) == -1)
   {
      printf("socket bind failed :(\n");
      exit(-1);
   }
   else
      printf("Socket successfully binded...\n");

   // server is ready to listen
   listen(socket_desc,3);

   // accept and incoming connection
   puts("Waiting for connection from client");
   c = sizeof(struct sockaddr_in);

   new_socket = accept(socket_desc,(struct sockaddr *)&client,(socklen_t *)&c);
   if(new_socket < 0)
   {
      puts("accept failed...\n");
      exit(0);
   }
   else
      printf("Accept successfully...\n");

   // function for getting IP address by domain name
   func(new_socket);

   close(socket_desc);

   return 0;
}