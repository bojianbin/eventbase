#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <signal.h>

#include "server_setting.h"

void setting_init(server_setting_t *setting)
{
	if(setting == NULL)
		return;
	
	setting->max_connections = 1024;
	setting->num_work_threads = 1;
	setting->server_port = 6737;

	return;
}

int daemonize(int _chdir, int close_stdfd)
{
    int fd;

    switch (fork()) 
	{
	    case -1:
	        return (-1);
	    case 0:
	        break;
	    default:
	        return (-1);
    }

    if (setsid() == -1)
        return (-1);

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

int sigignore(int sig) 
{
    struct sigaction sa = { .sa_handler = SIG_IGN, .sa_flags = 0 };

    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(sig, &sa, 0) == -1) {
        return -1;
    }
    return 0;
}

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
}

