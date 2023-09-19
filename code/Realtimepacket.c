//#include<netinet/in.h>
#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//strlen
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
//#include<netinet/udp.h>	//Provides declarations for udp header
//#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<unistd.h>
#include"PacketHeader.h"
void IPheader(unsigned char*,int);
void tcpPacket(unsigned char*,int);
void udpPacket(unsigned char*,int);
void icmpPacket(unsigned char*,int);
void Hexdata(unsigned char*,int);
int sslPacket(unsigned char*,int);
void CapturingPacket(unsigned char*,int);
int rawSocket;
struct sockaddr_in source,dest;
int ICMP_num=0,UDP_num=0,TCP_num=0,others=0,SSL_num=0,total=0,i,j;
FILE *fp;
char version[15]="";
char record_type[100]="";
int main(){
	int sockaddSize,dataSize;
	struct sockaddr saddr;
	struct in_addr in;
	unsigned char *buff = (unsigned char *)malloc(65536);
	printf("Starting .......\n");
	fp=fopen("info.txt","w+");
	if(fp==NULL){
		printf("Error on creating FILE.\n");
		return -5;
	}
	rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(rawSocket<0){
		printf("Socket creating ERROR.\n");
		return -2;// -2 defining as socket error
	}
	char tmp[] = "Packet No";
    printf("%-20s", tmp);
    //refresh();

    char tm[] = "IP Source Address";
    printf("%-20s", tm);
    //refresh();

    strcpy(tm, "IP Dest Address");
    printf("%-20s", tm);
    //refresh();

    strcpy(tm, "Protocol");
    printf("%-15s", tm);
    //refresh();

    strcpy(tm, "Source Port");
    printf("%-20s", tm);
    //refresh();

    strcpy(tm, "Dest Port");
    printf("%-20s", tm);
    //refresh();

    strcpy(tm, "Info");
    printf("%-20s\n", tm);
    //refresh();
    printf("\n");
	while(1){
		sockaddSize= sizeof(struct sockaddr);
		dataSize=recvfrom(rawSocket,buff,65536,0,&saddr,&sockaddSize);
		if(dataSize<0){
			printf("Receiving Failed. Failed to Capture Packets.\n");
			return -3;// Receiving failure defining as -3
		}
		CapturingPacket(buff,dataSize);
		sleep(1);	
	}
	close(rawSocket);
	printf("Complete.\n");
	return 0;
}
void CapturingPacket(unsigned char* buff,int dataSize){
	struct iphdr *ip=(struct iphdr*)buff;
	total++;
	switch (ip->protocol) {
		case 1:  
			ICMP_num++;
			icmpPacket(buff,dataSize);
			break;
		case 6: 
			TCP_num++;
			tcpPacket(buff , dataSize);
			break;
		
		case 17:
			UDP_num++;
			udpPacket(buff , dataSize);
			break;
		
		default: 
			++others;
			sleep(1);
			break;
	}
	//printf("TCP : %d   UDP : %d   ICMP : %d    Others : %d   Total : %d\n",TCP_num,UDP_num,ICMP_num,others,total);
}
void IPheader(unsigned char* buff, int dataSize)
{
	struct iphdr *ip = (struct iphdr *)buff;
	unsigned short iphdrlen;
	iphdrlen =ip->ihl*4;
	memset(&source, 0, sizeof(source));
	memset(&dest, 0, sizeof(dest));
	source.sin_addr.s_addr = ip->saddr;
	dest.sin_addr.s_addr = ip->daddr;
	unsigned int version = (unsigned int) ip->version;
	unsigned int tos = (unsigned int) ip->tos;
	unsigned int hdrln = ((unsigned int)(ip->ihl))*4;
	unsigned int TTL  = (unsigned int) ip->ttl;
	unsigned int protocol = (unsigned int) ip->protocol;
	fprintf(fp,"\n");
	fprintf(fp,"IP Header\n");
	fprintf(fp,"     Source IP         : %s\n",inet_ntoa(source.sin_addr));
	fprintf(fp,"     Destination IP    : %s\n",inet_ntoa(dest.sin_addr));
	fprintf(fp,"     IP Version        : %d\n",version);
	fprintf(fp,"     Protocol          : %d\n",protocol);
	fprintf(fp,"     IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(ip->tot_len));
	fprintf(fp,"     IP Header Length  : %d Bytes\n",hdrln);
	fprintf(fp,"     Type Of Service   : %d\n",tos);
	fprintf(fp,"     Identification    : %d\n",ntohs(ip->id));
	fprintf(fp,"     TTL               : %d\n",TTL);
	fprintf(fp,"     Checksum          : %d\n",ntohs(ip->check));
}

void tcpPacket(unsigned char* buff, int dataSize)
{
	char proto[30]="TCP";
	int flag=1;
	struct iphdr *ip = (struct iphdr *)buff;
	unsigned short iphdrlen;	
	iphdrlen = ip->ihl*4;
	struct tcphdr *tcp=(struct tcphdr*)(buff + iphdrlen);
	unsigned int fin = (unsigned int)tcp->fin;
	unsigned int hdrlen = (unsigned int)tcp->doff*4;
	unsigned int syn = (unsigned int)tcp->syn;
	unsigned int rst = (unsigned int)tcp->rst;
	unsigned int psh = (unsigned int)tcp->psh;
	unsigned int ack = (unsigned int)tcp->ack;
	unsigned int urg = (unsigned int)tcp->urg;	
	fprintf(fp,"***********************TCP Packet %d *************************\n",TCP_num);	
	IPheader(buff,dataSize);
	fprintf(fp,"\n");
	fprintf(fp,"TCP Header\n");
	fprintf(fp,"     Source Port          : %u\n",ntohs(tcp->source));
	fprintf(fp,"     Destination Port     : %u\n",ntohs(tcp->dest));
	fprintf(fp,"     Sequence Number      : %u\n",ntohl(tcp->seq));
	fprintf(fp,"     Acknowledge Number   : %u\n",ntohl(tcp->ack_seq));
	fprintf(fp,"     Header Length        : %d BYTES\n",hdrlen);
	fprintf(fp,"     Finish Flag          : %d\n",fin);
	fprintf(fp,"     Synchronise Flag     : %d\n",syn);
	fprintf(fp,"     Reset Flag           : %d\n",rst);
	fprintf(fp,"     Push Flag            : %d\n",psh);
	fprintf(fp,"     Acknowledgement Flag : %d\n",ack);
	fprintf(fp,"     Urgent Flag          : %d\n",urg);
	fprintf(fp,"     Window               : %d\n",ntohs(tcp->window));
	fprintf(fp,"     Checksum             : %d\n",ntohs(tcp->check));
	fprintf(fp,"     Urgent Pointer       : %d\n",tcp->urg_ptr);
	fprintf(fp,"\n");
	unsigned short datalen = dataSize - (iphdrlen+hdrlen); 
	// SSL LAYER CHECKING. IF THERE IS A SSL LAYER THEN PRINT THE INFO OF THE SSL LAYER
	flag=0;
	if((ntohs(tcp->source) == 443 || ntohs(tcp->dest == 443)) && sslPacket(buff+iphdrlen+hdrlen,datalen))
	{
		SSL_num++;
		printf("%-20d%-20s",total,inet_ntoa(source.sin_addr));
		printf("%-20s%-20s%-20d%-20d%-20s\n\n",inet_ntoa(dest.sin_addr),version,ntohs(tcp->source),ntohs(tcp->dest),record_type);
		flag=1;
	}
	 if(flag==0)
        {
            
            printf("%-20d%-20s", total, inet_ntoa(source.sin_addr));
            printf("%-20s%-20s%-20d%-20d%s %d ACK : %d\n\n", inet_ntoa(dest.sin_addr), proto, ntohs(tcp->source), ntohs(tcp->dest), "SYN : ", tcp->syn, tcp->ack);
            //refresh();
        }
	//Data in Hex
	fprintf(fp,"\n                         HEX DATA                         ");
	fprintf(fp,"\n");
	//IP header
	fprintf(fp,"\n*  *  *  *  *  *  *  *  * IP HEADER *  *  *  *  *  *  *  *  *\n");
	Hexdata(buff,iphdrlen);
	//TCP
	fprintf(fp,"\n*  *  *  *  *  *  *  *  *  TCP HEADER *  *  *  *  *  *  *  *\n");
	Hexdata(buff+iphdrlen,hdrlen);
	//Data
	fprintf(fp,"\n*  *  *  *  *  *  *  *  * DATA *  *  *  *  *  *  *  *  *  *\n");	
	Hexdata(buff + iphdrlen + hdrlen , datalen );
	fprintf(fp,"\n*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *\n\n");
}
void udpPacket(unsigned char *buff , int dataSize)
{
	struct iphdr *ip = (struct iphdr *)buff;
	unsigned short iphdrlen;
	iphdrlen = ip->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(buff + iphdrlen);
	
	fprintf(fp,"***********************UDP Packet %d *************************\n",UDP_num);
	//IP HEADER analysis
	IPheader(buff,dataSize);			
	//UDP analysis
	fprintf(fp,"\nUDP Header\n");
	fprintf(fp,"     Source Port      : %d\n" , ntohs(udph->source));
	fprintf(fp,"     Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(fp,"     UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(fp,"     UDP Checksum     : %d\n" , ntohs(udph->check));
	fprintf(fp,"\n");
	//IP header part
	fprintf(fp,"\n*  *  *  *  *  *  *  *  * IP HEADER *  *  *  *  *  *  *  *  *\n");
	Hexdata(buff , iphdrlen);
	//UDP part
	fprintf(fp,"\n*  *  *  *  *  *  *  *  *  UDP HEADER *  *  *  *  *  *  *  *\n");
	Hexdata(buff+iphdrlen , sizeof(udph));
	// DATA
	fprintf(fp,"\n*  *  *  *  *  *  *  *  * DATA *  *  *  *  *  *  *  *  *  *\n");	
	Hexdata(buff + iphdrlen + sizeof(udph),( dataSize - sizeof(udph) - iphdrlen ));
	
	fprintf(fp,"\n*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *\n\n");
	
}

void icmpPacket(unsigned char* buff , int dataSize)
{
	
	
	struct iphdr *ip = (struct iphdr *)buff;
	unsigned short iphdrlen;
	iphdrlen = ip->ihl*4;
	struct icmphdr *icmph = (struct icmphdr *)(buff + iphdrlen);
	fprintf(fp,"***********************ICMP Packet %d *************************\n",ICMP_num);	
	//IP header
	IPheader(buff , dataSize);	
	fprintf(fp,"\n");
	// ICMP part
	fprintf(fp,"ICMP Header\n");
	fprintf(fp,"    Type : %d",(unsigned int)(icmph->type));
	if((unsigned int)(icmph->type) == 11) 
		fprintf(fp,"  (TTL Expired)\n");
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
		fprintf(fp,"  (ICMP Echo Reply)\n");
	fprintf(fp,"    Code : %d\n",(unsigned int)(icmph->code));
	fprintf(fp,"    Checksum : %d\n",ntohs(icmph->checksum));
	fprintf(fp,"\n");
	//Ip hex
	fprintf(fp,"\n*  *  *  *  *  *  *  *  * IP HEADER *  *  *  *  *  *  *  *  *\n");
	Hexdata(buff,iphdrlen);
	//UDP hex	
	fprintf(fp,"\n*  *  *  *  *  *  *  *  * UDP HEADER *  *  *  *  *  *  *  *  *\n");
	Hexdata(buff + iphdrlen , sizeof(icmph));
	//Data hex
	fprintf(fp,"*  *  *  *  *  *  *  *  *  * DATA *  *  *  *  *  *  *  *  *  *\n");	
	Hexdata(buff + iphdrlen + sizeof(icmph),(dataSize - sizeof(icmph)- iphdrlen));
	fprintf(fp,"\n*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *\n\n");
	//refresh();
}

void Hexdata (unsigned char* data , int dataSize)
{
	
	for(i=0 ; i < dataSize ; i++)
	{
		if(i==0)fprintf(fp,"%06X ",i);
		else
		{
			if(i%16==8)fprintf(fp," =");
			else if(i%16==0)fprintf(fp,"\n%06X ",i);
			
		}	
		fprintf(fp," %02X",(unsigned int)data[i]);
		if(i+1==dataSize)fprintf(fp,"\n");
	}
}
int sslPacket(unsigned char* buff,int dataSize){
	
	if(dataSize<5)
	{
		return 0;
	}
	struct sslhdr *ssl =(struct sslhdr *)buff;
	int rec_type,ver1,ver2; 
	rec_type= (unsigned int)ssl->type;
	ver1= (unsigned int)ssl->ver1;
	ver2= (unsigned int)ssl->ver2;
	//SSL record layer content type
	switch(rec_type)
	{
		case 22:
			strcpy(record_type,"Handshake ");
			fprintf(fp,"********* SSL RECORD LAYER **********\n");
			fprintf(fp,"     Record Type: ");
			fprintf(fp,"Handshake\n");
			break;
		case 23:
			strcpy(record_type,"Application Data ");
			fprintf(fp,"********* SSL RECORD LAYER **********\n");
			fprintf(fp,"     Record Type: ");
			fprintf(fp,"Application Data\n");
			break;
		case 20:
			strcpy(record_type,"Change Cipher Spec ");
			fprintf(fp,"********* SSL RECORD LAYER **********\n");
			fprintf(fp,"     Record Type: ");
			fprintf(fp,"Change Cipher Spec\n");
			break;
		case 21 :
			strcpy(record_type,"Alert ");
			fprintf(fp,"********* SSL RECORD LAYER **********\n");
			fprintf(fp,"     Record Type: ");
			fprintf(fp,"Alert\n");
			break;
		default:
			return 0;
			
	}
	//Version
	fprintf(fp,"     Version: ");
	if(ver1==3 && ver2==1)
	{
		strcpy(version,"TLS 1.1");
		//printf("%s\n",version);
		fprintf(fp,"TLS 1.1\n");
	}
	else if(ver1==3 && ver2==2)
	{
		strcpy(version,"TLS 1.2");
		fprintf(fp,"TLS 1.2\n");
	}
	else if(ver1==3 && ver2==3)
	{
		strcpy(version,"TLS 1.3");
		fprintf(fp,"TLS 1.3\n");
	}
	else if(ver1==3 && ver2==0)
	{
		strcpy(version,"SSL 3.0");
		fprintf(fp,"SSL 3.0\n");
	}
	// LENGTH of the data.
	fprintf(fp,"     Length: ");
	fprintf(fp,"%d\n",ntohs(ssl->length));
	return 1; // indicating that it has ssl layer.
}


