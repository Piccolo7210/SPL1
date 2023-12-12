#ifndef HEADERS_INCLUDED
#define HEADERS_INCLUDED
#include <linux/types.h>
struct GlobalHeader
{
    u_int32_t magicNumber;
    u_int16_t versionMajor;
    u_int16_t versionMinor;
    u_int32_t time;
    u_int32_t sigfigs;
    u_int32_t snaplen;
    u_int32_t network;
};
struct PacketHeader
{
    u_int32_t tSec;
    u_int32_t tuSec;
    u_int32_t ocLen;
    u_int32_t packLen;
};

struct EthernetHeader
{
    u_char destination[6];
    u_char source[6];
    u_int16_t ethType;
};

struct tcphdr
{
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
    u_int16_t skip : 4;
    u_int16_t doff : 4;
    u_int16_t fin : 1;
    u_int16_t syn : 1;
    u_int16_t rst : 1;
    u_int16_t psh : 1;
    u_int16_t ack : 1;
    u_int16_t urg : 1;
    u_int16_t skip2 : 2;
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

struct udphdr
{
    u_int16_t source;
    u_int16_t dest;
    u_int16_t len;
    u_int16_t check;
};
struct sslhdr{
	u_char type;
	u_char ver1;
	u_char ver2;
	u_int16_t length;
};
struct flood
{
    u_int32_t IP[4];
    u_int64_t syn;
    u_int64_t syn_ack;
};
struct IP
{
    u_char IHL;
    u_char tos;
    u_int16_t length;
    u_int16_t id;
    u_int16_t fragment;
    u_char ttl;
    u_char protocol;
    u_int16_t checksum;
    u_char source[4];
    u_char destination[4];
};
struct TCP
{
    u_int16_t srcport;
    u_int16_t destport;
    u_int32_t seqNum;
    u_int32_t ackNUm;
    u_char tcp_resoff;
    u_char tcp_flag;
    u_int16_t tcp_win;
    u_int16_t tcp_checksum;
    u_int16_t tcp_urgptr;
};

#endif
