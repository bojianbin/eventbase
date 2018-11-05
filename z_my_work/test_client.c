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
struct sockaddr_in addr;
socklen_t len;

void sig_func_udp(int sig)
{
	int ret ;
	char *put_str = "hello\r\nhello\r\n";

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
void sig_func(int sig)
{
	int ret ;
	static int pos = -1;
	char *put_str = "hello\r\nhello\r\n";

	if(pos == -1)
	{
		
		pos = rand() % 14 ;
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

void * thread_func(void * arg)
{
	while(1)
	{
		if(mode_tcp)
			sig_func(0);
		else
			sig_func_udp(0);
		
		usleep(10000);
	}

	return NULL;
}
int main(int argc,char *argv[])
{
	char buf[1024] = {0};
	int ret;
	pthread_t tid;


	if(argc == 2 && strcmp(argv[1],"udp") == 0)
		mode_tcp = 0;
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
		signal(SIGQUIT,sig_func);
	else
		signal(SIGQUIT,sig_func_udp);
	
	srand(time(NULL));
	
	pthread_create(&tid,NULL,thread_func,NULL);
	if(mode_tcp)
	{
		int count = 0;
		while((ret = read(fd,buf,1024)) > 0)
		{
			printf("%d -> %s",count++,buf);
			memset(buf,0,1024);
		}
	}else
	{
		int count = 0;
		while((ret = recvfrom(fd,buf,1024,0,(struct sockaddr *)&addr,&len)) > 0)
		{
			printf("%d -> %s ",count++,buf);
			memset(buf,0,1024);
		}
	}
	return 0;
}

