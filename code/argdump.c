#include<stdio.h>
#include <fcntl.h> 
#include <signal.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include "icmpRead.h"
#include "hexdump.h"
#include "arpRead.h"
#include "SynFlood.h"
#include "Realtimepacket.h"
#include "dumpingfunc.h"
int main(int argc,char *arg[]){
	if(argc==1)
	pipeline();
	else if(argc==2)
	{	
		if(arg[1][0]=='-' && arg[1][1]=='L'){
			int x;
			printf("Enter the Protocol No:\n");
			printf("1.TCP\n");
			//printf("2.ARP\n");
			printf("2.ICMP\n");
			printf("3.UDP\n");
			scanf("%d",&x);
			Realtimepacket(x);
		}
		else{
			printf("Wrong Format!!!");
		}
	}
	else if(argc==3){
		if(arg[1][0]=='-' && arg[1][1]=='S'){
		SynFlood(arg[2]);	
		}
		printf("\n\n\n\n");
		sleep(1);
		commandLine(arg);
	}
}