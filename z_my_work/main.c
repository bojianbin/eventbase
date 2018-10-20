/*************************************************************************
	> File Name: sample.c
	> Author: 
	> Mail: 
	> Created Time: Fri 19 Oct 2018 04:27:48 PM CST
 ************************************************************************/

#include<stdio.h>
#include<signal.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<time.h>


#include"event2/event.h"
#include"event2/event_struct.h"


struct timeval _1_sec={.tv_sec=3,.tv_usec=0};

void time_func(evutil_socket_t fd, short flags, void *arg)
{
    struct event *timeevent = arg;

    printf("hello world %d %d\n",fd,flags);
    
    
    return;
}
void sigint_func(evutil_socket_t fd, short flags, void *arg)
{
    static int times = 0;

    if(++times >= 5)
    {
        event_del(arg);
    }
    printf("catch SIGINT %d %d\n",fd,flags);
    return;
}
int main()
{
    struct event_base *base = NULL;
    struct event timeevent;
    struct event sigintevent;

    base = event_base_new();
    
    /*
     * timeevent = event_new(base,-1,EV_PERSIST,time_func,timeevent);
     * sigintevent = evsignal_new(base,SIGINT,sigint_func,sigintevent);
    */
    event_assign(&timeevent,base,-1,EV_PERSIST,time_func,&timeevent);
    evsignal_assign(&sigintevent,base,SIGINT,sigint_func,&sigintevent);
    
    evtimer_add(&timeevent,&_1_sec);
    evtimer_add(&sigintevent,NULL);
    
    
    event_base_dispatch(base);

    event_base_free(base);

    return 0;
}
