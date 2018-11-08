/*************************************************************************
	> File Name: test_client.c
	> Author: 
	> Mail: 
	> Created Time: Sunday, November 04, 2018 AM02:14:40 CST
 ************************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "eventbase_anet.h"

int fd = -1;
int mode_tcp = 1;
int mode_stat = 0; //0:hello   1: stat   2:string
struct sockaddr_in addr;
socklen_t len;

void sig_func_udp_hello(int sig)
{
	int ret ;
	char *put_str = "hello\r\n\r\nhello\r\n\r\n";

	addr.sin_family = AF_INET;
	inet_pton(AF_INET,"127.0.0.1",&addr.sin_addr);
	addr.sin_port = htons(6737);
	len = sizeof(addr);

	ret = sendto(fd,put_str,strlen(put_str),0,(struct sockaddr *)&addr,len);
	if(ret != strlen(put_str))
	{
		printf("udp write error\n");
		exit(-1);
	}

	return;	
}
void sig_func_udp_stat(int sig)
{
	int ret ;
	char *put_str = "stat\r\n\r\n";

	addr.sin_family = AF_INET;
	inet_pton(AF_INET,"127.0.0.1",&addr.sin_addr);
	addr.sin_port = htons(6737);
	len = sizeof(addr);

	ret = sendto(fd,put_str,strlen(put_str),0,(struct sockaddr *)&addr,len);
	if(ret != strlen(put_str))
	{
		printf("udp write error\n");
		exit(-1);
	}

	return;	
}
void sig_func_udp_string(int sig)
{
	int ret ;
	static int num = 0;
	char buf[128] = {0};
	char *put_str = "string %d\r\n\r\n";

	addr.sin_family = AF_INET;
	inet_pton(AF_INET,"127.0.0.1",&addr.sin_addr);
	addr.sin_port = htons(6737);
	len = sizeof(addr);

	num++;
	sprintf(buf,put_str,num);
	ret = sendto(fd,buf,strlen(buf),0,(struct sockaddr *)&addr,len);
	if(num >= 10)
		num = 0;
	if(ret != strlen(buf))
	{
		printf("udp write error\n");
		exit(-1);
	}

	return;	
}

void sig_func_hello(int sig)
{
	int ret ;
	static int pos = -1;
	char *put_str = "hello\r\n\r\nhello\r\n\r\n";

	if(pos == -1)
	{
		
		pos = rand() % strlen(put_str) ;
		ret = write(fd,put_str,pos);
		if(ret != pos)
		{
			printf("write error\n");
			exit(-1);
		}
		
		
	}
	else
	{	
		ret = write(fd,put_str + pos,strlen(put_str) - pos);
		if(ret != strlen(put_str) - pos)
		{
			printf("write error\n");
			exit(-1);
		}
		pos = -1;
	}

	return ;
}

void sig_func_stat(int sig)
{
	int ret ;
	char *put_str = "stat\r\n\r\n";

	
		;
	ret = write(fd,put_str,strlen(put_str));
	if(ret != strlen(put_str))
	{
		printf("write error\n");
		exit(-1);
	}
	
	
	return ;
}
void sig_func_string(int sig)
{
	int ret ;
	static int num = 0;
	char buf[128] = {0};
	char *put_str = "string %d\r\n\r\n";


	num++;
	sprintf(buf,put_str,num);
	ret = write(fd,buf,strlen(buf));
	if(num >= 10)
		num = 0;
	if(ret != strlen(buf))
	{
		printf("write error\n");
		exit(-1);
	}

	return;	
}

void * thread_func(void * arg)
{
	while(1)
	{
		if(mode_tcp)
		{
			switch(mode_stat)
			{
				case 0:
					sig_func_hello(0);
					break;
				case 1:
					break;
				case 2:
					sig_func_string(0);
					break;
			}
		}
		else
		{
			switch(mode_stat)
			{
				case 0:
					sig_func_udp_hello(0);
					break;
				case 1:
					break;
				case 2:
					sig_func_udp_string(0);
					break;
			}
		}
		usleep(5000);
	}

	return NULL;
}
int main(int argc,char *argv[])
{
	char buf[2048] = {0};
	int ret;
	pthread_t tid;


	if(argc >= 2 && strcmp(argv[1],"udp") == 0)
		mode_tcp = 0;
	else
		mode_tcp = 1;
	
	if(argc >= 3 && strcmp(argv[2],"stat") == 0)
		mode_stat = 1;
	else if(argc >= 3 && strcmp(argv[2],"string") == 0)
		mode_stat = 2;
	else
		mode_stat = 0;
	
	if(mode_tcp)
		fd = anetTcpConnect(NULL, "127.0.0.1", 6737);
	else
		fd = socket(AF_INET,SOCK_DGRAM,0);
	if(fd < 0)
	{
		printf("connect error and we quit\n");
		exit(-1);
	}

	if(mode_tcp)
	{

		signal(SIGQUIT,sig_func_stat);
	}
	else
	{

		signal(SIGQUIT,sig_func_udp_stat);
	}
	
	srand(time(NULL));

	if(mode_stat != 1)//not stat
		pthread_create(&tid,NULL,thread_func,NULL);

	if(mode_tcp)
	{
		while((ret = read(fd,buf,2048)) > 0)
		{
			printf("%s",buf);
			if(mode_stat == 2)
				printf("\n");
			else
				fflush(stdout);
			memset(buf,0,2048);
		}
	}else
	{
		int count = 0;
		while((ret = recvfrom(fd,buf,2048,0,(struct sockaddr *)&addr,&len)) > 0)
		{
			printf("%s",buf);
			if(mode_stat == 2)
				printf("\n");
			else
				fflush(stdout);
			memset(buf,0,2048);
		}
	}
	return 0;
}



