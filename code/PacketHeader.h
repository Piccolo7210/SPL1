#ifndef HEADERS_INCLUDED
#define HEADERS_INCLUDED
#include <linux/types.h>
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
#endif
