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

#include "server_setting.h"
#include "event2/event.h"
#include "event2/event_struct.h"

extern server_setting_t g_setting;
int main()
{
	struct event_base *main_base = NULL;
	struct event_config *ev_config = NULL;

	sigignore(SIGPIPE);
	setting_init(&g_setting);
	setting_read(&g_setting);

	
    ev_config = event_config_new();
    event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
    main_base = event_base_new_with_config(ev_config);
    event_config_free(ev_config);

    return 0;
}
