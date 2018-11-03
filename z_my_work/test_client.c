/*************************************************************************
	> File Name: test_client.c
	> Author: 
	> Mail: 
	> Created Time: Sunday, November 04, 2018 AM02:14:40 CST
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "anet.h"

int main()
{
	char buf[1024] = {0};
	char *put_str = "hello\r\nhello\r\n";
	int fd,ret;

	fd = anetTcpConnect(NULL, "127.0.0.1", 6737);
	if(fd < 0)
	{
		printf("connect error and we quit\n");
		exit(-1);
	}

	ret = write(fd,put_str,strlen(put_str));
	if(ret != strlen(put_str))
	{
		printf("write error\n");
		exit(-1);
	}
	while((ret = read(fd,buf,1024)) > 0)
	{
		printf("%s",buf);
		memset(buf,0,1024);
	}

	return 0;
}

