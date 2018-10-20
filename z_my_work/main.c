/*************************************************************************
	> File Name: sample.c
	> Author: 
	> Mail: 
	> Created Time: Fri 19 Oct 2018 04:27:48 PM CST
 ************************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<time.h>


#include"event2/event.h"


struct timeval _1_sec={.tv_sec=1,.tv_usec=0};

void time_func(evutil_socket_t fd, short flags, void *arg)
{
    struct event *timeevent = arg;

    printf("hello world\n");
    
    
    return;
}
int main()
{
    struct event_base *base = NULL;
    struct event *timeevent;

    base = event_base_new();
    //timeevent = evtimer_new(base,time_func,timeevent);
    timeevent = event_new(base,-1,EV_PERSIST,time_func,timeevent);
    evtimer_add(timeevent,&_1_sec);
    
    
    event_base_dispatch(base);

    event_base_free(base);

    return 0;
}
