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
#define MX 100000
FILE *pf;
FILE *ses_fp;
char ptr[65536], p[65536];
int it, fit, color;
int s_k = 0;

struct flood track[MX];
long long spoof[MX], s = 0, tcp = 0, udp = 0, icmp = 0, http = 0, ssl = 0;
long long track_bound = -1, spoof_bound = -1;
struct http_ses
{
    u_char filename[100];

    u_int32_t IP_source[4];
    u_int32_t IP_destination[4];
    u_int16_t s_port;
    u_int16_t d_port;
    u_int32_t first_seqNum;
    u_int32_t prev_seq;
    u_int32_t prev_ack;

} html_ses[1000];


char ssl_inf[500];

int find_duplicate(long long k)
{

    for (int i = 0; i <= spoof_bound; i++)
    {
        if (spoof[i] == k)
            return 1;
    }
    return 0;
}

int is_same(int arr[], u_int32_t Addr[])
{
    for (int i = 0; i < 4; i++)
    {
        if (arr[i] != Addr[i])
            return 0;
    }

    return 1;
}

void checking_syn(int IPAddr[], int flag)
{

    long long k, f = 0;
    for (int i = 0; i <= track_bound; i++)
    {
        int l = is_same(IPAddr, track[i].IP);
        if (l)
        {
            f = 1;
            if (flag == 1)
            {
                k = track[i].syn;
                k++;
                track[i].syn = k;
            }
            else
            {
                k = track[i].syn_ack;
                k++;
                track[i].syn_ack = k;
            }

            break;
        }
    }

    if (f == 0)
    {
        track_bound++;

        for (int i = 0; i < 4; i++)
        {
            track[track_bound].IP[i] = IPAddr[i];
        }

        if (flag == 1)
        {
            track[track_bound].syn = 1;
            track[track_bound].syn_ack = 0;
        }
        else
        {
            track[track_bound].syn_ack = 1;
            track[track_bound].syn = 0;
        }
    }
}
void check_flood()
{

    for (int i = 0; i <= track_bound; i++)
    {
        if ((track[i].syn - track[i].syn_ack) > 20)
            spoof[++spoof_bound] = i;
    }
}

int SynFlood ()
{
    char fileName[100];
    strcpy(fileName,"SynFloodSample.pcap");
    struct GlobalHeader ghead;
    struct PacketHeader phead;
    struct EthernetHeader ehead;
    struct IP ip;
    struct TCP T;
    //struct udphdr U;
    //unsigned char c;
    unsigned char protocol;
    //unsigned short g;
    char flg[6];
    //int pd = 0;
    //int contains_pay = 1;

    int add_skip = 0;
    pf = fopen(fileName, "rb");
    

    fread(&ghead, sizeof(struct GlobalHeader), 1, pf);
    printf("Analysing packets\n\n");
    //refresh();

   // int p = 30;

    char tmp[] = "Packet No";
    //printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s", tmp);
    //refresh();

    char tm[] = "IP Source Address";
    //printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s", tm);
    //refresh();

    strcpy(tm, "IP Dest Address");
    //printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s", tm);
    //refresh();

    strcpy(tm, "Protocol");
   // printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s", tm);
    //refresh();

    strcpy(tm, "Source Port");
    //printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s", tm);
    //refresh();

    strcpy(tm, "Dest Port");
   // printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s", tm);
    //refresh();
    printf("\n");

    sleep(1);

    for (it = 0; !feof(pf); it++)
    {

        add_skip = 0;
        //pd = 0, contains_pay = 1;
        int ur = 0, ac = 0, ps = 0, rs = 0, sy = 0, fi = 0;
        char src_ip[100], dest_ip[100];
        int src, des;
        fread(&phead, sizeof(struct PacketHeader), 1, pf);
        fread(&ehead, sizeof(struct EthernetHeader), 1, pf);
        add_skip += 14;
        ehead.ethType = ntohs(ehead.ethType);
        
        if (ehead.ethType == 2048)
        {
            fread(&ip, sizeof(struct IP), 1, pf);
            add_skip += 20;
           //unsigned short p;
             unsigned short len;
            //p = ip.IHL >> 4;
            len = (ip.IHL & 0x0f);
            protocol = ip.protocol;

            int arr[4], arr2[4];
            int lm = 0, km = 0;

            for (int i = 0; i < 4; i++)
            {
            
                arr[lm++] = (int)ip.source[i];
                src = (int)ip.source[i];
                int j = 0;
                char rev[4];
                while (src != 0)
                {
                    rev[j++] = (src % 10) + '0';
                    src /= 10;
                }
                if (j == 0)
                    rev[j++] = '0';
                for (int kl = j - 1; kl >= 0; kl--)
                    src_ip[km++] = rev[kl];
                if (i != 3)
                {
                   
                    src_ip[km++] = '.';
                }
            
                   
            }
            src_ip[km] = '\0';

            lm = 0;
            km = 0;
            for (int i = 0; i < 4; i++)
            {
               
                des = (int)ip.destination[i];
                int j = 0;
                char rev[4];
                while (des != 0)
                {
                    rev[j++] = (des % 10) + '0';
                    des /= 10;
                }
                if (j == 0)
                    rev[j++] = '0';
                for (int kl = j - 1; kl >= 0; kl--)
                    dest_ip[km++] = rev[kl];
                arr2[lm++] = (int)ip.destination[i];

                if (i != 3)
                {
                   
                    dest_ip[km++] = '.';
                }
            }
            dest_ip[km] = '\0';

           // int i = 0;
            len = len * 4;
           // pd = phead.ocLen - (ntohs(ip.length) + 14);
            int skip = len - 20;
            while (skip > 0)
            {
                add_skip++;
                fgetc(pf);
                skip--;
            }
            //char ch;

            if (protocol == 6)
            {
                //color = Blue;
                strcpy(tm, "TCP");
                
                tcp++;
                fread(&T, sizeof(struct TCP), 1, pf);
                add_skip += 20;
                unsigned short hl = (T.tcp_resoff & 0xf0) >> 4;

                // if ((ntohs(ip.length) - (len + (hl * 4))) == 0)
                // {
                //     contains_pay = 0;
                // }
                skip = (hl * 4) - 20;

                while (skip > 0)
                {
                    add_skip++;
                    fgetc(pf);
                    skip--;
                }
                src = ntohs(T.srcport);
                des = ntohs(T.destport);

                if ((src == 443) || (des == 443))
                {
                    ssl++;
                    //color = Magenta;
                    strcpy(tm, "SSL");
                }
                else if (ntohs(T.srcport) == 80 || ntohs(T.destport) == 80)
                {

                    //color = Yellow;
                    strcpy(tm, "HTTP");
                
                    http++;
                }

                int j = 0;
                for (int i = 32; i >= 1; i = i >> 1)
                {
                    if (T.tcp_flag & i)
                        flg[j++] = 1;
                    else
                        flg[j++] = 0;
                }

                for (int i = 0; i < 6; i++)
                {
                    if (i == 0)
                    {
                     
                        ur = flg[i];
                    }

                    if (i == 1)
                    {

                        
                        ac = flg[i];
                    }

                    if (i == 2)
                    {
                        
                        ps = flg[i];
                    }

                    if (i == 3)
                    {
                       
                        rs = flg[i];
                    }

                    if (i == 4)
                    {
                        sy = flg[i];
                    }

                    if (i == 5)
                    {
                        fi = flg[i];
                    }
                }
                if (sy == 1 && ac == 1 && ur == 0 && fi == 0 && ps == 0 && rs == 0)
                {

                    checking_syn(arr, 2);
                }
                else if (sy == 1 && ac == 0 && ur == 0 && fi == 0 && ps == 0 && rs == 0)
                {

                    checking_syn(arr2, 1);
                }
                   printf("%-20d%-20s%-20s%-20s%-20d%-20d\n", it + 1, src_ip, dest_ip, tm, src, des);
            }

            T.srcport = 0;
            T.destport = 0;
        }

        else
        {
            
            //skipping
            for (int bb = 0; bb < phead.ocLen - 14; bb++)
            fgetc(pf);
        }
        add_skip = 0;
    }
   // print(White);
    printf("-----------------------------SUMMARY-----------------------------\n");
    printf("TCP : %lld\nhttp : %lld\nssl : %lld\n", tcp,http,ssl);

    check_flood();
    if (spoof_bound >= 0)
    {
       // print(Red);
        printf("Warning!\n");
    }
    if (spoof_bound >= 0)
    {

        printf("IP ADDRESSES that are in a risk of getting ATTACKED :");
    }

    for (int i = 0; i <= spoof_bound; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            if (j != 3)
                printf("%d.", track[i].IP[j]);
            else
                printf("%d", track[i].IP[j]);
        }
        printf("(Number of received SYN packets is %ld && Number of sent SYN_ACKs is %ld)\n", track[i].syn, track[i].syn_ack);
    }
    //refresh();

    return 0;
}
