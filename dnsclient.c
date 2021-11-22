#include <stdio.h>  //printf
#include <stdlib.h> //malloc
#include <unistd.h> //getpid
#include <string.h> //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>

// List of DNS Servers registered on the system
char dns_servers[10][100];
int dns_server_count = 0;

// Types of DNS resource records :)
#define T_A 1   // IPv4 address
#define T_NS 2  // Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6   // start authority zone
#define T_PTR 12  // domain name pointer
#define T_MX 15   // Mail server

// Function Prototypes
void ngethostbyname(unsigned char*, int);
void changeToDnsNameFormat(unsigned char*, unsigned char*);
unsigned char* ReadName(unsigned char*, unsigned char*, int*);
void get_dns_servers();

// DNS header structure
struct DNS_HEADER
{
   unsigned short id;        // identification number
   unsigned char rd :1;      // recursion desired
   unsigned char tc :1;      // truncated message
   unsigned char aa :1;      // authoritive answer
   unsigned char opcode :4;  // purpose of message
   unsigned char qr :1;      // query/response flag

   unsigned char rcode :4;   // response code
   unsigned char cd :1;      // checking disabled
   unsigned char ad :1;      // authenticated data
   unsigned char z :1;       // its z! reserved
   unsigned char ra :1;      // recursion available

   unsigned short q_count;   // number of question entries
   unsigned short ans_count; // number of answer entries
   unsigned short auth_count;// number of authority entries
   unsigned short add_count; // number of resource entries
};

// Constant sized fields of query structure
struct QUESTION
{
   unsigned short qtype;
   unsigned short qclass;
};

// Constant sized fields of the resource record structure
#pragma pack(push,1)
struct R_DATA
{
   unsigned short type;
   unsigned short _class;
   unsigned int ttl;
   unsigned short data_len;
};
#pragma pack(pop)

// Pointers to resource record contents
struct RES_RECORD
{
   unsigned char *name;
   struct R_DATA *resource;
   unsigned char *rdata;
};

// Structure of a query
typedef struct
{
   unsigned char *name;
   struct QUESTION *ques;
}QUERY;

/* ---------- main function ---------- */
int main(int argc,char *argv[])
{
   unsigned char hostname[100];

   // Get the DNS servers from the resolv.conf file
   get_dns_servers();

   // Get the hostname from the terminal
   printf("Enter the Hostname to Lookup: ");
   scanf("%s",hostname);

   // Get the IP address of the hostname , A record
   ngethostbyname(hostname,T_A);

   return 0;
}

/* Perform a DNS Query by sending a packet */
void ngethostbyname(unsigned char *host,int query_type)
{
   unsigned char buf[65336], *qname, *reader;
   int i, j, stop, s;

   struct sockadd_in a;

   struct RES_RECORD answer[20], auth[20], addit[20]; // the replies from the DNS server
   struct sockaddr_in dest;

   struct DNS_HEADER *dns = NULL;
   struct QUESTION *qinfo = NULL;

   printf("Resolving %s ",host);

   s = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); // UDP packet for DNS queries

   dest.sin_family = AF_INET;
   dest.sin_port = htons(53);
   dest.sin_addr.s_addr = inet_addr(dns_servers[0]);  // DNS servers

   // Set the DNS structure to standard queries
   dns = (struct DNS_HEADER *)&buf;

   dns->id = (unsigned short) htons(getpid());
   dns->qr = 0;      // This is a query
   dns->opcode = 0;  // This is a standard query
   dns->aa = 0;      // Not authoritative
   dns->tc = 0;      // This message is not truncated
   dns->rd = 1;      // Recursion desired
   dns->ra = 0;      // Recursion are not available!
   dns->z = 0;
   dns->ad = 0;
   dns->cd = 0;
   dns->rcode = 0;
   dns->q_count = htons(1);  // we have only 1 question
   dns->ans_count = 0;
   dns->auth_count = 0;
   dns->add_count = 0;

   // point to the query portion
   qname = (unsigned char*)&buf[sizeof(struct DNS_HEADER)];

   changeToDnsNameFormat(qname,host);
   qinfo = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]  // fill it

   qinfo->qtype = htons( query_type ); // type of query, A, MX, CNAME, NS etc
   qinfo->qclass = htons(1);           // its internet

   // Sending a packet
   printf("\nSending packet...");
   if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0 )
   {
      perror("Send to failed");
   }
   printf("Done");

   // Receive the answer from the server
   i = sizeof(dest);
   printf("\nReceiving answer...");
   if( recvfrom(s,(char*)buf,65536,0,(struct sockaddr*)&dest,(socklen_t*)&i) < 0 )
   {
      perror("Receive from failed");
   }
   printf("Done");

   dns = (struct DNS_HEADER)&buf;

   // move ahead of the dns header and the query field
   reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

   printf("\nThe response contains: ");
   printf("\n %d Questions.",ntohs(dns->q_count));
   printf("\n %d Answer.",ntohs(dns->ans_count));
   printf("\n %d Authoritative servers.",ntohs(dns->auth_count));
   printf("\n %d Additional records.",ntohs(dns->add_count));

   // Start reading answer
   stop = 0;
   for(i=0;i<ntohs(dns->ans_count);i++)
   {
      answers[i].name = ReadName(reader,buf,&stop);
      reader = reader + stop;

      answers[i].resource = (struct R_DATA*)(reader);
      reader = reader + sizeof(struct R_DATA);

      if(ntohs(answers[i].resource->type) == 1 ) // if its an IPv4 address
      {
         answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

         for(j=0;j<ntohs(answers[i].resource->data_len);j++)
         {
            answers[i].rdata[j] = reader[j];
         }

         answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

         reader = reader + ntohs(answers[i].resource->data_len);
      }
      else
      {
         answers[i].rdata = ReadName(reader,buf,&stop);
         reader = reader + stop;
      }
   }

   // read authorities
   for(i=0;i<ntohs(dns->auth_count);i++)
   {
      auth[i].name = ReadName(reader,buf,&stop);
      reader += stop;

      auth[i].resource = (struct R_DATA*)(reader);
      reader += sizeof(struct R_DATA);

      auth[i].rdata = ReadName(reader,buf,&stop);
      reader += stop;
   }

   // read additional
   for(i=0;i<ntohs(dns->add_count);i++)
   {
      addit[i].name = ReadName(reader,buf,&stop);
      reader += stop;

      addit[i].resource = (struct R_DATA*)(reader);
      reader += sizeof(struct R_DATA);

      if(ntohs(addit[i].resource->type) == 1)
      {
         addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));

         for(j=0;j<ntohs(addit[i].resource->data_len);j++)
         {
            addit[i].rdata[j] = reader[j];
         }

         addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
         reader += ntohs(addit[i].resource->data_len);
      }
      else
      {
         addit[i].rdata = ReadName(reader,buf,&stop);
         reader += stop;
      }
   }

   // print answers
   printf("\nAnswer Records : %d \n",ntohs(dns->ans_count));
   for(i=0;i<ntohs(dns->ans_count);i++)
   {
      printf("Name: %s",answers[i].name);

      if( ntohs(answers[i].resource->type) == T_A)  // IPv4 address
      {
         long *p;
         p = (long *p)answers[i].rdata;
         a.sin_addr.s_addr = (*p);      // working without ntoh1
         printf(" has IPv4 address : %s",inet_ntoa(a.sin_addr));
      }

      if( ntohs(answers[i].resource->type) == 5)
      {
         // canonical name for an alias
         printf("has alias name : %s",answers[i].rdata);
      }

      printf("\n");
   }

   // print authorities
   printf("\nAuthoritive Records : %d \n",ntohs(dns->auth_count));
   for(i=0;i<ntohs(dns->auth_count);i++)
   {
      printf("Name : %s",auth[i].name);
      if( ntohs(auth[i].resource->type) == 2)
      {
          printf("has nameserver : %s",auth[i].rdata);
      }
      printf("\n")
   }

   // print additional resource records
   printf("\nAdditional Records : %d \n": ntohs(dns->add_count));
   for(i=0;i<ntohs(dns->add_count);i++)
   {
      printf("Name : %s",addit[i].name);
      if(ntohs(addit[i].resource->type) == 1)
      {
         long *p;
         p = (long *)addit[i].rdata;
         a.sin_addr.s_addr = (*p);
         printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
      }
      printf("\n");
   }

   return 0;
}
