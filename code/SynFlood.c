#include<stdio.h>	
#include<stdlib.h>	
#include<string.h>		
#include<netinet/ip.h>	
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<unistd.h>
#include"PacketHeader.h"
#define MAX 100000

FILE *filepointer;
char fileName[100];
int pacekt_no;
long  int fake_ip[MAX],tcp = 0, http = 0, ssl = 0;
long int  false_no = -1, fake_num = -1;
struct Synfld spam[MAX];


int is_same(int address1[], u_int32_t address2[]);
void checking_syn(int address[], int flag);
void check_flood();
int SynFlood (char *pcapfile);


int SynFlood (char *pcapfile)
{
    struct globalhdr Global;
    struct packethdr packet_head;
    struct ethernethdr ether;
    struct IP Iphead;
    struct TCP Tcphead;
    unsigned char protocol;
    char flg[6];
    char temp[] = "IP Source Address";
    strcpy(fileName,pcapfile);
    filepointer = fopen(fileName, "rb");
    

    fread(&Global, sizeof(struct globalhdr), 1, filepointer);
    printf("Analysing packets\n\n");
    printf("%-20s", "Packet No");
    printf("%-20s", temp);
    strcpy(temp, "IP Dest Address");
    printf("%-20s", "IP Dest Address");
    strcpy(temp, "Protocol");
    printf("%-20s", "Protocol");
    strcpy(temp, "Source Port");
    printf("%-20s", "Source Port");
    strcpy(temp, "Dest Port");
    printf("%-20s", "Dest Port");
    printf("\n");
    sleep(1);
tcp= 0;
http= 0;
ssl=0;
  while(!feof(filepointer))
    {
        //printf("ssl : %lld\n\n ",ssl);
        char source_ip[100], destination_ip[100];
        int source, destination,source_port,destination_port;
        
        fread(&packet_head, sizeof(struct packethdr), 1,filepointer);
        
        
        fread(&ether, sizeof(struct ethernethdr), 1, filepointer);
        ether.ethType = ntohs(ether.ethType);
        
        
        if (ether.ethType == 2048)
        {
            unsigned short len;
            fread(&Iphead, sizeof(struct IP), 1, filepointer);
    
            len = (Iphead.IHL & 0x0f);
            
            protocol = Iphead.protocol;

            int address1[4], address2[4];
            int q = 0, z = 0;

            for (int i = 0; i < 4; i++)
            {
                int j = 0;
                char reverse_ip[4];
                address1[q++] = (int)Iphead.source[i];
                source = (int)Iphead.source[i];
                
                if (source == 0)
                reverse_ip[j++] = '0';
                for(j=0;source!=0;j++)
                {
                    reverse_ip[j] = (source % 10) + '0';
                    source /= 10;
                }
                
                for (int m = j - 1; m >= 0; m--)
                source_ip[z++] = reverse_ip[m];
                
                if (i < 3)
                source_ip[z++] = '.';
            }
            source_ip[z] = '\0';
            q = 0;
            z = 0;
            for (int i = 0; i < 4; i++)
            {
                int j = 0;
                char reverse_ip[4];
                destination = (int)Iphead.destination[i];
                address2[q++] = (int)Iphead.destination[i];
                
                if (destination == 0) 
                    reverse_ip[j++] = '0';
                else
                {
                     for(j=0;destination!=0;j++)
                     {
                        reverse_ip[j] = (destination % 10) + '0';
                        destination /= 10;
                     }
                }

                for (int m= j - 1; m >= 0; m--)
                    destination_ip[z++] = reverse_ip[m];
                

                if (i < 3)
                    destination_ip[z++] = '.';
            }
            destination_ip[z] = '\0';
            len = len * 4;
            int skip = len - 20;
            while (skip > 0)
            {
         
                fgetc(filepointer);
                skip--;
            }
  
            
            if (protocol == 6)
            {
                tcp=tcp+1;
                strcpy(temp, "TCP");
                
                fread(&Tcphead, sizeof(struct TCP), 1, filepointer);
                source_port = ntohs(Tcphead.srcport);
                destination_port = ntohs(Tcphead.destport);
    
                unsigned short hl = (Tcphead.tcp_resoff & 0xf0) >> 4;

                skip = (hl * 4) - 20;

                while (skip > 0)
                {
                    fgetc(filepointer);
                    skip--;
                }

                if (source_port==443 || destination_port==443)
                {
                    ssl+=1;
                    strcpy(temp, "SSL");
                }
                else if (ntohs(Tcphead.srcport) == 80 || ntohs(Tcphead.destport) == 80)
                {
                    strcpy(temp, "HTTP(TCP)");
                    http+=1;
                }

                int j = 0;
                for (int i = 32; i >= 1; i = i >> 1)
                {
                    if (Tcphead.tcp_flag & i)
                        flg[j++] = 1;
                    else
                        flg[j++] = 0;
                }
        		int urgent = 0;
        		int ack = 0;
        		int  push = 0;
        		int reset = 0;
       	 		int  syn = 0; 
        		int fin = 0;
                for (int i = 0; i < 6; i++)
                {
                     switch(i){
                        case 0 : urgent = flg[i];
                                break;
                        case 1 : ack = flg[i];
                                break;
                        case 2 : push = flg[i];
                                break;
                        case 3 : reset = flg[i];
                                break;
                        case 4 : syn = flg[i];
                                break;
                        case 5 : fin = flg[i];
                                break;
                    }
                }
                if (syn == 1 && ack == 0 && urgent == 0 && fin == 0 && push == 0 && reset == 0)
                {

                    checking_syn(address1, 1);
                }
                else if (syn == 1 && ack == 1 && urgent == 0 && fin == 0 && push == 0 && reset == 0)
                {

                    checking_syn(address2, 2);
                }
                   printf("%-20d%-20s%-20s%-20s%-20d%-20d\n", pacekt_no+ 1, source_ip, destination_ip, temp, source_port, destination_port);
            }
        }
        else
        {
            for (int m = 0; m< packet_head.ocLen - 14; m++)
            fgetc(filepointer); // Skipping if it is not Ip header.
        }
        pacekt_no++;
    }
    printf("------------------------------------------TOTAl----------------------------------------------\n");
    printf("TCP = %ld\thttp = %ld\tssl = %ld\n", tcp,http,ssl);

    check_flood();
    
    if (fake_num >= 0)
    {

        printf("Syn-Flood Detected.\nIp addresses which got attacked:\n");
        for (int i = 0; i <= fake_num; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                printf("%d", spam[fake_ip[i]].IP[j]);
                
                if (j < 3)
                    printf(".");
                
                    
            }
            printf("SYN Packets Received : %ld\n",spam[i].syn);
            printf("SYN_ACK Packets Sent : %ld\n",spam[i].syn_ack);
        }

    }

    return 0;
}

int is_same(int address1[], u_int32_t address2[])
{
    for (int i = 0; i < 4; i++)
    {
        if (address1[i] != address2[i])
            return 0;
    }

    return 1;
}

void checking_syn(int address[], int s_a)
{

    long int syn_val;
    long int flag = 0;
    int same;
    same=0;
    long int i , ind;
    for (  i = 0; i <= false_no; i++)
    {
       
        same = is_same(address, spam[i].IP); // checking if both the ip address is same r not
        if(same!=0){
         ind =i;
            break;
        }
    }
    if (same==1)
        {
            flag = 1;
            if (s_a == 1)// s_a means Syn or Syn-ack? 1 for Syn and 2 for Syn-ack
            {
                syn_val = spam[ind].syn;
                syn_val++;
                spam[ind].syn = syn_val;
            }
            else
            {
                syn_val = spam[ind].syn_ack;
                syn_val++;
                spam[ind].syn_ack = syn_val;
            }
        }

    if (flag == 0)
    {
    	false_no++;
        for (int i = 0; i < 4; i++)
        spam[false_no].IP[i] = address[i];
        
        if (s_a == 1)
        {
            spam[false_no].syn = 1;
            spam[false_no].syn_ack = 0;
        }
        else
        {
            spam[false_no].syn_ack = 1;
            spam[false_no].syn = 0;
        }
        
    }
}
void check_flood()
{

    for (long int i = 0; i <= false_no; i++)
    {
        if ((spam[i].syn - spam[i].syn_ack) > 20)
            fake_ip[++fake_num] = i;
    }
}
