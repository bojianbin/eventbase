#ifndef _EVENTBASE_SERVER_SETTING__h
#define _EVENTBASE_SERVER_SETTING__h

#ifdef __cplusplus
extern "C"
{
#endif


#define SETTING_CFG_FILE "./eventbase.cfg"


typedef enum
{
	VALUE_UINT,
	VALUE_INT,
	VALUE_DOUBLE,
	VALUE_STRING
}value_type_e;
typedef struct
{
	char * section;
	char * keyname;
	void * addr;
	value_type_e type;
	int len;
	char *comment;
}key_value_t;

typedef struct
{
	int num_work_threads;
	int server_port;
	int max_connections;

	int max_user_rbuf;			/*user read buffer size*/
	int user_copy_wbuf; 		/*copy buffer size*/
	int socket_wbuf;    		/*SO_SNDBUF option*/
	int max_data_sending;   	/*max size of the data to send,0 if no limit*/
	int max_mute_time;          /*max no-interaction socket time,0 if no limit,in seconds*/
}server_setting_t;

extern server_setting_t g_setting;

void setting_init(server_setting_t *setting);
int setting_read();
int setting_write();
int daemonize(int _chdir, int close_stdfd);
int sigignore(int sig);
int adjust_max_fd(int max_conns);

#ifdef __cplusplus
}
#endif





#endif
