#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <signal.h>

#include "eventbase_server_setting.h"
#include "iniparser.h"

server_setting_t g_setting;

static key_value_t setting_parse[] = 
{
	{"COMMON","num_worker_threads",	&g_setting.num_work_threads,	VALUE_INT,	
		sizeof(g_setting.num_work_threads),"number of worker threads"},
	{"COMMON","server_port",		&g_setting.server_port,			VALUE_INT, 	
		sizeof(g_setting.server_port),"server listen port.both tcp and udp"},
	{"COMMON","max_connections",	&g_setting.max_connections,		VALUE_INT,	
		sizeof(g_setting.max_connections),"server max connections"},
	{"DETAIL","max_user_rbuf",		&g_setting.max_user_rbuf,		VALUE_INT,	
		sizeof(g_setting.max_user_rbuf),NULL},
	{"DETAIL","user_copy_wbuf",		&g_setting.user_copy_wbuf,		VALUE_INT,	
		sizeof(g_setting.user_copy_wbuf),NULL},
	{"DETAIL","socket_wbuf",		&g_setting.socket_wbuf,		VALUE_INT,	
		sizeof(g_setting.socket_wbuf),NULL},
	{"DETAIL","user_data_sending",		&g_setting.max_data_sending,		VALUE_INT,	
		sizeof(g_setting.max_data_sending),"max size of the data to send"},
	{"DETAIL","max_mute_time",		&g_setting.max_mute_time,		VALUE_INT,	
		sizeof(g_setting.max_mute_time),NULL}
};

/**
 *  fill in default params
 * 
 * @note: 
 *
 *
 * @param[in] setting	  	:setting structure
 *
 * @return: void
 */
void setting_init(server_setting_t *setting)
{
	if(setting == NULL)
		return;
	
	setting->max_connections = 1024;
	setting->num_work_threads = 3;
	setting->server_port = 6737;

	setting->max_user_rbuf = 5120;
	setting->user_copy_wbuf = 2048;
	setting->socket_wbuf = 16384;
	setting->max_data_sending = setting->socket_wbuf + setting->user_copy_wbuf + 20480;
	setting->max_mute_time = 60;//seconds
	
	return;
}

/**
 *  read and parse params from config file 
 * 
 * @note: 
 *		file name SETTING_CFG_FILE
 * 		rewrite config file if the config file doesn't cover all params
 *
 * @param[in] null
 *
 * @return: 0 if success . -1 if error
 */
int setting_read()
{
	int i = 0, ret = 0;
	const char * ret_string = NULL;
	int not_found = 0;
	char key_buf[512] = {0};

	
	dictionary * dict =  iniparser_load(SETTING_CFG_FILE);
	if(dict != NULL)
	{
		for( i = 0 ; i < sizeof(setting_parse)/sizeof(setting_parse[0]) ; i++)
		{
			snprintf(key_buf,sizeof(key_buf),"%s:%s",setting_parse[i].section,setting_parse[i].keyname);
			switch(setting_parse[i].type)
			{
				case VALUE_UINT:
				case VALUE_INT:
					ret = iniparser_getint(dict, key_buf, -1);
					if(ret != -1)
					{
						*(int *)(setting_parse[i].addr) = ret ;
					}else
					{
						not_found = 1;
					}
					break;
				case VALUE_DOUBLE:
					ret = iniparser_getdouble(dict, key_buf, -1);
					if(ret != -1)
					{
						*(double *)(setting_parse[i].addr) = ret ;
					}else
					{
						not_found = 1;
					}
					break;
				case VALUE_STRING:
					ret_string = iniparser_getstring(dict, key_buf, "UNDEF");
					if(strcmp(ret_string,"UNDEF") != 0)
					{
						strncpy((char *)setting_parse[i].addr,ret_string,setting_parse[i].len);
					}else
					{
						not_found = 1;
					}
					break;
				default:
					break;
			}
		}

	}else
	{
		not_found = 1;
	}
	
	if(not_found == 1)
	{
		setting_write();
	}
	
	return 0;
}

/**
 *  write setting to config file
 * 
 * @note: 
 *		filename SETTING_CFG_FILE.
 *
 * @param[in] null
 *
 * @return: 0 if success . -1 if error
 */
int setting_write()
{
	FILE *fp ;
	int i,ret; 
	char tmp_str[512];
	char tmp_section[512] = {0};
	int section_write_once = 0;
	struct flock file_wr_lock = {F_WRLCK,SEEK_SET,0,0,0};
	
	
	if ((fp = fopen(SETTING_CFG_FILE, "w")) == NULL) 
	{
		return -1;
	}

	fcntl(fileno(fp),F_SETLKW,&file_wr_lock);
	
	strncpy(tmp_section,setting_parse[0].section,sizeof(tmp_section));
	for( i = 0; i < sizeof(setting_parse)/sizeof(setting_parse[0]) ; )
	{
		/*write section */
		for ( ; i < sizeof(setting_parse)/sizeof(setting_parse[0]) && 
			strcmp(setting_parse[i].section,tmp_section) == 0; i++) 
		{
			if (!section_write_once) 
			{
				fprintf(fp, "[%s]\n", setting_parse[i].section);
				section_write_once = 1;
			}
			if(setting_parse[i].comment != NULL)
				fprintf(fp,"#%s\n",setting_parse[i].comment);
			switch (setting_parse[i].type) {
			case VALUE_UINT:
				fprintf(fp,"%s = %u\n", setting_parse[i].keyname, *(unsigned int *)setting_parse[i].addr);
				break;
			case VALUE_DOUBLE:
				fprintf(fp,"%s = %lf\n", setting_parse[i].keyname, *(double *)setting_parse[i].addr);
				break;
			case VALUE_INT:
				fprintf(fp,"%s = %d\n", setting_parse[i].keyname, *(int *)setting_parse[i].addr);
				break;
			case VALUE_STRING:
				memset(tmp_str, 0, sizeof(tmp_str));
				strncpy(tmp_str, (char *)setting_parse[i].addr, sizeof(tmp_str)-1);
				fprintf(fp,"%s = %s\n", setting_parse[i].keyname, tmp_str);
				break;
			}	
		}
		fprintf(fp,"\n");

		if(i < sizeof(setting_parse)/sizeof(setting_parse[0]))
		{
			strncpy(tmp_section,setting_parse[i].section,sizeof(tmp_section));
			section_write_once = 0;
		}
		
	}

	fflush(fp);
	fsync(fileno(fp));
	/*file lock is released here*/
	fclose(fp);

	return 0;
}

/**
 *  daemonize process
 * 
 * @note: 
 *
 *
 * @param[in] _chdir	  	:change process current dir "/"
 * @param[in] close_stdfd	:close fd 0,1 and 2
 *
 * @return: 0 if success . -1 if error
 */
int daemonize(int _chdir, int close_stdfd)
{
    int fd;

	if (fork() != 0) 
		exit(0); /* parent exits */

	setsid(); /* create a new session */

    if (_chdir == 1) 
	{
        if(chdir("/") != 0) 
		{
            perror("chdir");
            return (-1);
        }
    }

    if (close_stdfd == 1 && (fd = open("/dev/null", O_RDWR, 0)) != -1) 
	{
        if(dup2(fd, STDIN_FILENO) < 0) 
		{
            perror("dup2 stdin");
            return (-1);
        }
        if(dup2(fd, STDOUT_FILENO) < 0) 
		{
            perror("dup2 stdout");
            return (-1);
        }
        if(dup2(fd, STDERR_FILENO) < 0) 
		{
            perror("dup2 stderr");
            return (-1);
        }

        if (fd > STDERR_FILENO) 
		{
            if(close(fd) < 0) 
			{
                perror("close");
                return (-1);
            }
        }
    }
	
    return (0);
}

/**
 *  ignore signal 
 * 
 * @note: 
 *
 *
 * @param[in] sig	  :signal
 *
 * @return: 0 if success . -1 if error
 */
int sigignore(int sig) 
{
    struct sigaction sa = { .sa_handler = SIG_IGN, .sa_flags = 0 };

    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(sig, &sa, 0) == -1) {
        return -1;
    }
    return 0;
}

/**
 *  Adjust process maximum file descriptor 
 * 
 * @note: 
 *
 *
 * @param[in] max_conns	  :user main structure
 *
 * @return: 0 if success . -1 if error
 */
int adjust_max_fd(int max_conns)
{
	struct rlimit rlim;
	
    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) 
	{
        return -1;
    } else 
	{
        rlim.rlim_cur = max_conns;
        rlim.rlim_max = max_conns;
        if (setrlimit(RLIMIT_NOFILE, &rlim) != 0)
		{
            return -1;
        }
    }

	return 0;
}
