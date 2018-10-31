/*************************************************************************
	> File Name: threads.c
	> Author: 
	> Mail: 
	> Created Time: Mon 29 Oct 2018 04:53:58 PM CST
 ************************************************************************/
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <string.h>
#include <sys/prctl.h>

#include "anet.h"
#include "server_setting.h"
#include "threads.h"
#include "event2/event.h"
#include "event2/event_struct.h"

static EVENT_THREAD *threads = NULL;
conn_t **conns = NULL;
static conn_queue_item_t *cqi_freelist = NULL;
static pthread_mutex_t cqi_freelist_lock = PTHREAD_MUTEX_INITIALIZER;
volatile unsigned int current_time = 0;
static conn_t *listen_conn = NULL;



/*
 * Initializes a connection queue.
 */
static void cq_init(conn_queue_t *cq) 
{
    pthread_mutex_init(&cq->lock, NULL);
    cq->head = NULL;
    cq->tail = NULL;
}

/*
 * Looks for an item on a connection queue, but doesn't block if there isn't
 * one.
 * Returns the item, or NULL if no item is available
 */
static conn_queue_item_t *cq_pop(conn_queue_t *cq) 
{
    conn_queue_item_t *item;

    pthread_mutex_lock(&cq->lock);
    item = cq->head;
    if (NULL != item) 
	{
        cq->head = item->next;
        if (NULL == cq->head)
            cq->tail = NULL;
    }
    pthread_mutex_unlock(&cq->lock);

    return item;
}

/*
 * Adds an item to a connection queue.
 */
static void cq_push(conn_queue_t *cq, conn_queue_item_t *item) 
{
    item->next = NULL;

    pthread_mutex_lock(&cq->lock);
    if (NULL == cq->tail)
        cq->head = item;
    else
        cq->tail->next = item;
    cq->tail = item;
    pthread_mutex_unlock(&cq->lock);
}

/*
 * Returns a fresh connection queue item.
 */
static conn_queue_item_t *cqi_new(void) 
{
    conn_queue_item_t *item = NULL;
	
    pthread_mutex_lock(&cqi_freelist_lock);
    if (cqi_freelist) 
	{
        item = cqi_freelist;
        cqi_freelist = item->next;
    }
    pthread_mutex_unlock(&cqi_freelist_lock);

    if (NULL == item) 
	{
        int i;

        /* Allocate a bunch of items at once to reduce fragmentation */
        item = malloc(sizeof(conn_queue_item_t) * ITEMS_PER_ALLOC);
        if (NULL == item) 
		{
            return NULL;
        }

        /*
         * Link together all the new items except the first one
         * (which we'll return to the caller) for placement on
         * the freelist.
         */
        for (i = 2; i < ITEMS_PER_ALLOC; i++)
            item[i - 1].next = &item[i];

        pthread_mutex_lock(&cqi_freelist_lock);
        item[ITEMS_PER_ALLOC - 1].next = cqi_freelist;
        cqi_freelist = &item[1];
        pthread_mutex_unlock(&cqi_freelist_lock);
    }

    return item;
}


/*
 * Frees a connection queue item (adds it to the freelist.)
 */
static void cqi_free(conn_queue_item_t *item) 
{
    pthread_mutex_lock(&cqi_freelist_lock);
    item->next = cqi_freelist;
    cqi_freelist = item;
    pthread_mutex_unlock(&cqi_freelist_lock);
}

/*
 * Initializes the connections array. We don't actually allocate connection
 * structures until they're needed, so as to avoid wasting memory when the
 * maximum connection count is much higher than the actual number of
 * connections.
 *
 * This does end up wasting a few pointers' worth of memory for FDs that are
 * used for things other than connections, but that's worth it in exchange for
 * being able to directly index the conns array by FD.
 */
static void conn_init(void) 
{
    /* We're unlikely to see an FD much higher than maxconns. */
    int next_fd = dup(1);
	/* account for extra unexpected open FDs */
    int headroom = 10;
    struct rlimit rl;
	int max_fds = 0;

    max_fds = g_setting.max_connections + headroom + next_fd;

    /* But if possible, get the actual highest FD we can possibly ever see. */
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) 
	{
        max_fds = rl.rlim_max;
    } else 
	{
        fprintf(stderr, "Failed to query maximum file descriptor; "
                        "falling back to maxconns\n");
    }

    close(next_fd);

    if ((conns = calloc(max_fds, sizeof(conn_t *))) == NULL)
	{
        fprintf(stderr, "Failed to allocate connection structures\n");
        /* This is unrecoverable so bail out early. */
        exit(1);
    }
}

void conn_free(conn_t *c) 
{
    if (c) 
	{
        conns[c->sfd] = NULL;
        if (c->msglist)
            free(c->msglist);
        if (c->rbuf)
            free(c->rbuf);
        if (c->wbuf)
            free(c->wbuf);
        if (c->iov)
            free(c->iov);
        free(c);
    }
}
void event_handler(const int fd, const short which, void *arg) ;
conn_t *conn_new(const int sfd, enum conn_states init_state,
                const int event_flags,
                const int read_buffer_size, enum network_transport transport,
                struct event_base *base) 

{
    conn_t *c;

    c = conns[sfd];

    if (NULL == c) 
	{
        if (!(c = (conn_t *)calloc(1, sizeof(conn_t)))) 
		{
            return NULL;
        }

        c->rbuf = c->wbuf = 0;
        c->iov = 0;
        c->msglist = 0;

        c->rsize = read_buffer_size;
        c->wsize = DATA_BUFFER_SIZE;
        c->iovsize = IOV_LIST_INITIAL;
        c->msgsize = MSG_LIST_INITIAL;

        c->rbuf = (char *)malloc((size_t)c->rsize);
        c->wbuf = (char *)malloc((size_t)c->wsize);
        c->iov = (struct iovec *)malloc(sizeof(struct iovec) * c->iovsize);
        c->msglist = (struct msghdr *)malloc(sizeof(struct msghdr) * c->msgsize);

        if (c->rbuf == 0 || c->wbuf == 0 || c->iov == 0 ||
                c->msglist == 0) 
       	{
            conn_free(c);
            fprintf(stderr, "Failed to allocate buffers for connection\n");
            return NULL;
        }

        c->sfd = sfd;
        conns[sfd] = c;
    }

    c->transport = transport;
    
    c->request_addr_size = sizeof(c->request_addr);
  

    if (transport == tcp_transport && init_state == conn_new_cmd) 
	{
        if (getpeername(sfd, (struct sockaddr *) &c->request_addr,
                        &c->request_addr_size)) {
            perror("getpeername");
            memset(&c->request_addr, 0, sizeof(c->request_addr));
        }
    }

    c->state = init_state;
    c->rbytes = c->wbytes = 0;
    c->wcurr = c->wbuf;
    c->rcurr = c->rbuf;
    c->iovused = 0;
    c->msgcurr = 0;
    c->msgused = 0;
    c->last_cmd_time = current_time; /* initialize for idle kicker */


    c->write_and_go = init_state;
    c->write_and_free = 0;


    event_assign(&c->event, base,sfd, event_flags, event_handler, (void *)c);
    c->ev_flags = event_flags;

    if (event_add(&c->event, NULL) == -1) 
	{
        perror("event_add");
        return NULL;
    }

    return c;
}

/*
 * Sets a connection's current state in the state machine. Any special
 * processing that needs to happen on certain state transitions can
 * happen here.
 */
static void conn_set_state(conn_t *c, enum conn_states state) 
{
    if (state != c->state) 
	{
        c->state = state;
    }
}
static void conn_cleanup(conn_t *c) 
{
    if(c == NULL)
		return;

    if (c->write_and_free) 
	{
        free(c->write_and_free);
        c->write_and_free = 0;
    }

    if (c->transport == udp_transport) 
	{
        conn_set_state(c, conn_read);
    }
}

static void conn_close(conn_t *c) 
{
    if(c == NULL)
		return;

    /* delete the event, the socket and the conn */
    event_del(&c->event);
    conn_cleanup(c);

    conn_set_state(c, conn_closed);
    close(c->sfd);

    return;
}


/*
 * Dispatches a new connection to another thread. This is only ever called
 * from the main thread, either during initialization (for UDP) or because
 * of an incoming connection.
 */
void dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags,
                       int read_buffer_size, enum network_transport transport) {

	static int last_thread = -1;
	conn_queue_item_t *item = cqi_new();
    char buf[1];
	
    if (item == NULL) 
	{
        close(sfd);
        /* given that malloc failed this may also fail, but let's try */
        fprintf(stderr, "Failed to allocate memory for connection object\n");
        return ;
    }

    int tid = (last_thread + 1) % g_setting.num_work_threads;

    EVENT_THREAD *thread = threads + tid;

    last_thread = tid;

    item->sfd = sfd;
    item->init_state = init_state;
    item->event_flags = event_flags;
    item->read_buffer_size = read_buffer_size;
    item->transport = transport;

    cq_push(thread->new_conn_queue, item);

    buf[0] = 'c';
    if (write(thread->notify_send_fd, buf, 1) != 1) 
	{
        perror("Writing to thread notify pipe");
    }
}

read_status_e try_read_udp(conn_t *c)
{
	int ret = 0;
    c->request_addr_size = sizeof(c->request_addr);
    ret = recvfrom(c->sfd, c->rbuf, c->rsize,
                   0, (struct sockaddr *)&c->request_addr,
                   &c->request_addr_size);

	if(ret > 0)
	{
		c->rbytes = ret;
        c->rcurr = c->rbuf;
		
		return READ_SOME_DATA;
	}
	
	return READ_NONE;
}
read_status_e try_read_network(conn_t *c) 
{
    read_status_e gotdata = READ_ERROR;
    int res;
    

    if (c->rcurr != c->rbuf) 
	{
        if (c->rbytes != 0) /* otherwise there's nothing to copy */
            memmove(c->rbuf, c->rcurr, c->rbytes);
        c->rcurr = c->rbuf;
    }

    while (1) 
	{
        if (c->rbytes >= c->rsize) 
		{
			int new_size = 0;
			if(c->rsize == g_setting.max_user_rbuf)
			{
				return gotdata;
			}
			if(c->rsize * 2 >= g_setting.max_user_rbuf)
				new_size = g_setting.max_user_rbuf;
			else
				new_size = c->rsize * 2;
            char *new_rbuf = realloc(c->rbuf, new_size);
            if (!new_rbuf) 
			{
                return READ_ERROR;
            }
            c->rcurr = c->rbuf = new_rbuf;
            c->rsize = new_size;
        }

        int avail = c->rsize - c->rbytes;
        res = read(c->sfd, c->rbuf + c->rbytes, avail);
        if (res > 0) 
		{
            c->rbytes += res;
            if (res == avail) 
			{
				gotdata = READ_SOME_DATA;
                continue;
            } else 
			{
				gotdata = READ_DATA_DONE;
                break;
            }
        }
        if (res == 0) 
		{
            return READ_ERROR;
        }
        if (res == -1) 
		{
            if (errno == EAGAIN || errno == EWOULDBLOCK) 
			{
                break;
            }
            return READ_ERROR;
        }
    }
	
    return gotdata;
}

void drive_machine(conn_t *c)
{
	int stop = false;
	int sfd;
	socklen_t addrlen;
    struct sockaddr_storage addr;
	
	if(c == NULL)
		return;

	while(stop == false)
	{
		switch(c->state)
		{
			case conn_listening:
				sfd = accept(c->sfd, (struct sockaddr *)&addr, &addrlen);

	            if (sfd < 0) 
				{
	                perror("accept()");
	                if (errno == EAGAIN || errno == EWOULDBLOCK) 
					{
	                    /* these are transient, so don't log anything */
	                    stop = true;
	                } else if (errno == EMFILE) 
	                {
	                	/*too many open fds*/
	                    stop = true;
	                } else 
					{
	                    stop = true;
	                }
	                break;
	            }
	           
				anetNonBlock(NULL, sfd);

	            if (sfd >= g_setting.max_connections - 1) 
	           	{
	                close(sfd);
					stop = true;
	            } else 
				{
	                dispatch_conn_new(sfd, conn_new_cmd, EV_READ | EV_PERSIST,
	                                     DATA_BUFFER_SIZE, c->transport);
	            }
	            
				break;
			case conn_waiting:
				conn_set_state(c, conn_read);
            	stop = true;
			
				break;
			case conn_read:
				break;
			case conn_parse_cmd:
				break;
			case conn_new_cmd:
				break;
			case conn_nread:
				break;
			case conn_swallow:
				break;
			case conn_write:
				break;
			case conn_mwrite:
				break;
			case conn_closing:
				break;
			case conn_closed:
	            /* This only happens if dormando is an idiot. */
	            abort();
	            break;
       		case conn_watch:
            	/* We handed off our connection to the logger thread. */
            	stop = 1;
            	break;
        	case conn_max_state:
            	break;
		}
	}


	return;
}
void event_handler(const int fd, const short which, void *arg) 
{
    conn_t *c;

    c = (conn_t *)arg;

    c->which = which;

    /* sanity */
    if (fd != c->sfd) 
	{
        conn_close(c);
        return;
    }

    drive_machine(c);

    /* wait for next event */
    return;
}

/*
 * Processes an incoming "handle a new connection" item. This is called when
 * input arrives on the libevent wakeup pipe.
 */
static void thread_libevent_process(int fd, short which, void *arg) 
{
    EVENT_THREAD *me = arg;
    conn_queue_item_t *item;
    char buf[1];
    conn_t *c;
    unsigned int timeout_fd;

    while(read(fd, buf, 1) == 1) 
	{
	    switch (buf[0]) 
		{
		    case 'c':
		        item = cq_pop(me->new_conn_queue);

		        if (NULL == item) 
				{
		            break;
		        }

		        c = conn_new(item->sfd, item->init_state, item->event_flags,
		                           item->read_buffer_size, item->transport,
		                           me->base);
		        if (c == NULL) 
				{
		            if (item->transport == udp_transport) 
					{
		                fprintf(stderr, "Can't listen for events on UDP socket\n");
		                exit(1);
		            } else 
					{
		                close(item->sfd);
		            }
		        } else 
		       	{
		            c->thread = me;
		        }


		        cqi_free(item);
		        break;
	    }
    }
}

static void setup_thread(EVENT_THREAD *me) 
{
    struct event_config *ev_config;
    ev_config = event_config_new();
    event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
    me->base = event_base_new_with_config(ev_config);
    event_config_free(ev_config);

    if (! me->base) 
	{
        fprintf(stderr, "Can't allocate event base\n");
        exit(1);
    }

    /* Listen for notifications from other threads */
    event_assign(&me->notify_event,me->base, me->notify_receive_fd,EV_READ | EV_PERSIST, thread_libevent_process, me);

    if (event_add(&me->notify_event, NULL) == -1) 
	{
        fprintf(stderr, "Can't monitor libevent notify pipe\n");
        exit(1);
    }

    me->new_conn_queue = malloc(sizeof(conn_queue_t));
    if (me->new_conn_queue == NULL) 
	{
        perror("Failed to allocate memory for connection queue");
        exit(-1);
    }

	pthread_mutex_init(&me->new_conn_queue->lock, NULL);
    me->new_conn_queue->head = NULL;
    me->new_conn_queue->tail = NULL;

	return;

}

static void *worker_libevent(void *arg) 
{
	char thread_name[32] = {0};
    EVENT_THREAD *me = arg;

	sprintf(thread_name,"event_%d",me - threads + 1);
	prctl(PR_SET_NAME,thread_name);
	
    event_base_dispatch(me->base);

    event_base_free(me->base);
	
    return NULL;
}

static void create_worker(void *(*func)(void *), void *arg) 
{
    pthread_attr_t  attr;
    int             ret;

    pthread_attr_init(&attr);

    if ((ret = pthread_create(&((EVENT_THREAD*)arg)->thread_id, &attr, func, arg)) != 0) 
	{
        perror("Can't create thread");
        exit(1);
    }

	return;
}


void eventbase_thread_init(int nthreads) 
{
    int         i;
	int 		ret ;
    int         power;

    threads = calloc(nthreads, sizeof(EVENT_THREAD));
    if (! threads) 
	{
        perror("Can't allocate thread descriptors");
        exit(1);
    }

    for (i = 0; i < nthreads; i++) 
	{
        int fds[2];
        if (pipe(fds)) 
		{
            perror("Can't create notify pipe");
            exit(1);
        }
		ret = anetNonBlock(NULL, fds[0]);
		ret += anetNonBlock(NULL, fds[1]);
		if(ret != 0)
		{
			perror("Can not set nonblock");
        	exit(1);
		}
        threads[i].notify_receive_fd = fds[0];
        threads[i].notify_send_fd = fds[1];

        setup_thread(&threads[i]);
    }

    /* Create threads after we've done all the libevent setup. */
    for (i = 0; i < nthreads; i++) 
	{
        create_worker(worker_libevent, &threads[i]);
    }

	return;
}

int eventbase_data_init()
{
	conn_init();

	return 0;
}

int server_socket_init(int port,struct event_base *main_base)
{
	int i = 0;
	int tcp_fd = -1, udp_fd = -1;
	conn_t *listen_conn_add;

	if(port < 0) 
		goto ERR;

	tcp_fd = anetTcpServer(NULL, port, NULL , 100);
	if(tcp_fd < 0) 
		goto ERR;
	anetNonBlock(NULL, tcp_fd);
	
	udp_fd = anetUdpServer(NULL, port, NULL);
	if(udp_fd < 0 )
		goto ERR;

	for( i = 0 ; i < g_setting.num_work_threads ; i++)
	{
		int per_thread_fd = i != 0 ? dup(udp_fd) : udp_fd;
		dispatch_conn_new(per_thread_fd, conn_read,EV_READ | EV_PERSIST,UDP_READ_BUFFER_SIZE, udp_transport);
	}
	
	listen_conn_add = conn_new(tcp_fd, conn_listening,EV_READ | EV_PERSIST, 1,tcp_transport, main_base);

	listen_conn_add->next = listen_conn;
	listen_conn = listen_conn_add;

	return 0;
ERR:
	if(tcp_fd >= 0 ) close(tcp_fd);
	if(udp_fd >= 0) close(udp_fd);
	return -1;
}

