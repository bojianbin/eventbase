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
#include "server_setting.h"
#include "threads.h"
#include "event2/event.h"
#include "event2/event_struct.h"

static EVENT_THREAD *threads;
conn_t **conns;
static conn_queue_item_t *cqi_freelist;
static pthread_mutex_t cqi_freelist_lock = PTHREAD_MUTEX_INITIALIZER;
volatile unsigned int current_time;


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

void drive_machine(conn_t *c)
{
	int stop = 0;
	if(c == NULL)
		return;

	while(!stop)
	{
		switch(c->state)
		{
			case conn_listening:
				break;
			case conn_waiting:
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

    if (read(fd, buf, 1) != 1) 
	{
        fprintf(stderr, "Can't read from libevent pipe\n");
        return;
    }

    switch (buf[0]) {
    case 'c':
        item = cq_pop(me->new_conn_queue);

        if (NULL == item) {
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
        } else {
            c->thread = me;
        }


        cqi_free(item);
        break;
    /* we were told to pause and report in */
    case 'p':
        //register_thread_initialized();
        break;
    /* a client socket timed out */
    case 't':
        if (read(fd, &timeout_fd, sizeof(timeout_fd)) != sizeof(timeout_fd)) 
		{
            return;
        }
        //conn_close_idle(conns[timeout_fd]);
        break;
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
    EVENT_THREAD *me = arg;


    event_base_loop(me->base, 0);

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


void eventbase_thread_init(int nthreads, void *arg) 
{
    int         i;
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

        threads[i].notify_receive_fd = fds[0];
        threads[i].notify_send_fd = fds[1];

        //setup_thread(&threads[i]);
    }

    /* Create threads after we've done all the libevent setup. */
    for (i = 0; i < nthreads; i++) 
	{
        create_worker(worker_libevent, &threads[i]);
    }

	return;
}

