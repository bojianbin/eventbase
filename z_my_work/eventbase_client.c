/*************************************************************************
	> File Name: eventbase_client.c
	> Author: 
	> Mail: 
	> Created Time: Tue 06 Nov 2018 04:26:50 PM CST
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

#include "linenoise.h"

//1 : tcp 2:udp
int net_mode = -1;
int tcp_fd = -1;
int udp_fd = -1;
char  remote_ip[128];
char  remote_port[128];
char prompt_hits[128];
struct sockaddr_in addr;
socklen_t len;
pthread_t udp_thread_id;
pthread_t tcp_thread_id;


/*assume _str is in heap. just use that*/
char ** c_split_args(char *_str,int *_argc)
{
	char ** ret_array = NULL;
	char * ptr = _str;

	*_argc = 0;

	for(;*ptr != '\0' ;)
	{

		while(*ptr != '\0' && *ptr == ' ' )
	    {		
            *ptr = '\0';
            ptr++;
        }
		if(*ptr == '\0')
			return ret_array;
		*_argc = *_argc + 1;
		if(*_argc == 1)
			ret_array = (char **)malloc(sizeof(char *));
		else
			ret_array = (char **)realloc(ret_array,*_argc * sizeof(char *));

		ret_array[*_argc - 1] = ptr;

		while(*ptr != '\0' && *ptr != ' ' )
			ptr++;
	}

	return ret_array;
	
}

void send_udp(char *arg)
{
	int ret ;
	char buf[2048] = {0};

	if(strlen(remote_ip) == 0 || strlen(remote_port) == 0)
	{
		return ;
	}
	
	addr.sin_family = AF_INET;
	inet_pton(AF_INET,remote_ip,&addr.sin_addr);
	addr.sin_port = htons(atoi(remote_port));
	len = sizeof(addr);

	ret = sendto(udp_fd,arg,strlen(arg),0,(struct sockaddr *)&addr,len);
	if(ret != strlen(arg))
	{
		printf("udp write error\n");
	}

	while((ret = recvfrom(udp_fd,buf,2048,0,(struct sockaddr *)&addr,&len)) > 0)
	{
		printf("%s",buf);
		memset(buf,0,2048);
	}
	
	return;	
}
void send_tcp(char * arg)
{
	int ret;

	if(tcp_fd < 0)return;
	ret = write(tcp_fd,arg,strlen(arg));
	if(ret != strlen(arg))
	{
		printf("tcp write error\n");
	}

	char buf[2048] = {0};
	while((ret = read(tcp_fd,buf,2048)) > 0)
	{	
		int i = 0;
		while( i < ret )
		{
			if(buf[i] == '\r')
				buf[i] = ' ';
			i++;
		}
		printf("%s",buf);
		memset(buf,0,2048);
	}	

	return;
}
void *udp_read_thread(void * arg)
{
	int ret = 0;
	char buf[2048] = {0};

	pthread_detach(pthread_self());
	while((ret = recvfrom(udp_fd,buf,2048,0,(struct sockaddr *)&addr,&len)) > 0)
	{
		printf("%s",buf);
		fflush(stdout);
		memset(buf,0,2048);
	}

	return NULL;
}
void *tcp_read_thread(void *arg)
{
	int ret = 0;
	char buf[2048] = {0};

	pthread_detach(pthread_self());
	while((ret = read(tcp_fd,buf,2048)) > 0)
	{	
		int i = 0;
		while( i < ret )
		{
			if(buf[i] == '\r')
				buf[i] = ' ';
			i++;
		}
		printf("%s",buf);
		fflush(stdout);
		memset(buf,0,2048);
	}	

	return NULL;
}

void completion(const char *buf, linenoiseCompletions *lc) 
{
    if (buf[0] == 'c') 
	{
        linenoiseAddCompletion(lc,"connect");
        linenoiseAddCompletion(lc,"connect 127.0.0.1");
		linenoiseAddCompletion(lc,"connect 127.0.0.1 6737");
    }
	if (buf[0] == 's') 
	{
        linenoiseAddCompletion(lc,"send ");
    }
	if (buf[0] == 't') 
	{
        linenoiseAddCompletion(lc,"tcp");
    }
	if (buf[0] == 'u') 
	{
        linenoiseAddCompletion(lc,"udp");
    }
}

char *hints(const char *buf, int *color, int *bold) 
{
    if (!strcasecmp(buf,"hello")) 
	{
        *color = 35;
        *bold = 0;
        return " World";
    }
    return NULL;
}


int main(int argc, char **argv) 
{
    char *line;
    char *prgname = argv[0];
	char **_argv = NULL;
	int _argc = 0;


	linenoiseSetMultiLine(1);
    /* Set the completion callback. This will be called every time the
     * user uses the <tab> key. */
    linenoiseSetCompletionCallback(completion);
    linenoiseSetHintsCallback(hints);

    /* Load history from file. The history file is just a plain text file
     * where entries are separated by newlines. */
    linenoiseHistoryLoad("history.txt"); /* Load the history at startup */

    /* Now this is the main loop of the typical linenoise-based application.
     * The call to linenoise() will block as long as the user types something
     * and presses enter.
     *
     * The typed string is returned as a malloc() allocated string by
     * linenoise, so the user needs to free() it. */
    sprintf(prompt_hits,"disconnected >");
	linenoiseHistorySetMaxLen(20);
    while((line = linenoise(prompt_hits)) != NULL) 
	{
		if(strlen(line) == 0)
			continue;
		linenoiseHistoryAdd(line); 
        linenoiseHistorySave("history.txt"); 

		_argv = c_split_args(line, &_argc);

		if(strcmp(_argv[0],"connect") == 0)
		{
			if(strlen(remote_ip)!=0 && strlen(remote_port) != 0 && 
				(strcmp(_argv[1],remote_ip) != 0 ||
				strcmp(_argv[2],remote_port) != 0)
				)
			{
				close(tcp_fd);
				tcp_fd = -1;
			}
			
			tcp_fd = anetTcpConnect(NULL, _argv[1], atoi(_argv[2]));
			if(tcp_fd < 0)
			{
				printf("anetTcpConnect error\n");
			}else
			{
				strcpy(remote_ip,_argv[1]);
				strcpy(remote_port,_argv[2]);
				net_mode = 1 ;//default  tcp mode
				sprintf(prompt_hits,"%s:%s %s >",remote_ip,remote_port,"tcp");
			}
			anetRcvTimeout(NULL, tcp_fd, 3000);
			//pthread_create(&tcp_thread_id,NULL,tcp_read_thread,NULL);
		}else if(strcmp(_argv[0],"tcp") == 0)
		{
			net_mode = 1 ;
			sprintf(prompt_hits,"%s:%s %s >",remote_ip,remote_port,"tcp");
		}else if(strcmp(_argv[0],"udp") == 0)
		{
			net_mode = 2 ;
			sprintf(prompt_hits,"%s:%s %s >",remote_ip,remote_port,"udp");
			if(udp_fd == -1)
			{
				udp_fd = socket(AF_INET,SOCK_DGRAM,0);
				anetRcvTimeout(NULL, udp_fd, 3000);
				//pthread_create(&udp_thread_id,NULL,udp_read_thread,NULL);
			}
		}else if(strcmp(_argv[0],"send") == 0)
		{
			char *pos = NULL;
			char *ptr = _argv[1];
			/*;; = \r\n   that's protocol end flag now*/
			while((pos = strstr(ptr,";;") )!= NULL)
			{
				*pos++ = '\r';
				*pos++ = '\n';
				ptr = pos;
			}
			if(net_mode == 1)
				send_tcp(_argv[1]);
			else if(net_mode == 2)
				send_udp(_argv[1]);
			else
				printf("unconnected\n");
		}else if(strcmp(_argv[0],"quit") == 0 || strcmp(_argv[0],"exit") == 0)
		{
			printf("Quit now!\n");
			exit(0);
		}else if(strcmp(_argv[0],"clear") == 0 )
		{
			linenoiseClearScreen();
		}else
		{
			printf("unrecognized command\n");
		}
       
        free(line);
		free(_argv);
    }
    return 0;
}


