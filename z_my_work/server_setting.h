
typedef struct
{
	int num_work_threads;
	int server_port;
	int max_connections;
	
}server_setting_t;

void setting_init(server_setting_t *setting);
int daemonize(int _chdir, int close_stdfd);
int sigignore(int sig);
int adjust_max_fd(int max_conns);



