/*************************************************************************
	> File Name: sample.c
	> Author: 
	> Mail: 
	> Created Time: Fri 19 Oct 2018 04:27:48 PM CST
 ************************************************************************/

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/prctl.h>

#include "eventbase_threads.h"
#include "eventbase_server_setting.h"
#include "event2/event.h"
#include "event2/event_struct.h"

extern server_setting_t g_setting;
int main()
{
	int ret;
	struct event_base *main_base = NULL;
	struct event_config *ev_config = NULL;
	
	setting_init(&g_setting);
	setting_read(&g_setting);

	sigignore(SIGPIPE);
	daemonize(0,0);
	adjust_max_fd(g_setting.max_connections);
	
	ev_config = event_config_new();
    event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
    main_base = event_base_new_with_config(ev_config);
    event_config_free(ev_config);
	
	eventbase_data_init(main_base);
	eventbase_thread_init(g_setting.num_work_threads);
	ret = eventbase_server_socket(g_setting.server_port,main_base);
	if(ret < 0)
	{
		printf("server_socket_init error\n");
		exit(-1);
	}
	
	prctl(PR_SET_NAME,"event_main");
	/*main loop*/
	event_base_dispatch(main_base);


	event_base_free(main_base);
	
    return 0;
}
