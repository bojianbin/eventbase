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

#include "eventbase_anet.h"
#include "eventbase_server_setting.h"
#include "eventbase_threads.h"
#include "eventbase_cmd_parse.h"
#include "event2/event.h"
#include "event2/event_struct.h"
#include "cJSON.h"

static event_thread_t 	*threads = NULL;
static server_stat_t   	server_stats;

conn_t **conns = NULL;
static conn_queue_item_t *cqi_freelist = NULL;
static pthread_mutex_t cqi_freelist_lock = PTHREAD_MUTEX_INITIALIZER;
volatile unsigned int current_time = 0;
static conn_t *listen_conn = NULL;
static struct event clockevent;



static void add_thread_conn(event_thread_t * thread,conn_t * c)
{
	if(thread->conn_list == NULL)
	{
		thread->conn_list = c;
		c->next = NULL;
		c->pre = NULL;
	}else
	{
		thread->conn_list->pre = c;
		c->next = thread->conn_list;
		c->pre = NULL;
		thread->conn_list = c;
	}
}
static void remove_thread_conn(event_thread_t * thread,conn_t * c)
{
	if(thread->conn_list == c)
	{
		thread->conn_list = c->next;
	}else{
		c->pre->next = c->next;
		if(c->next)
			c->next->pre = c->pre; 
	}
}
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
void event_whandler(const int fd, const short which, void *arg) ;

static int add_msghdr(conn_t *c);
conn_t *conn_new(const int sfd, conn_states_e init_state,
                const int event_flags,
                const int read_buffer_size, network_transport_e transport,
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
        c->wsize = g_setting.user_copy_wbuf;
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
  

    if (transport == tcp_transport ) 
	{
        if (getpeername(sfd, (struct sockaddr *) &c->request_addr,
                        &c->request_addr_size)) 
       	{
            memset(&c->request_addr, 0, sizeof(c->request_addr));
        }
    }

    c->state = init_state;
    c->rbytes = c->wbytes = 0;
    c->wcurr = c->wbuf;
    c->rcurr = c->rbuf;
    c->iovused = 0;
	c->iovcurr = 0;
    c->msgcurr = 0;
    c->msgused = 0;
    c->last_cmd_time = current_time; /* initialize for idle kicker */

    event_assign(&c->event, base,sfd, event_flags, event_handler, (void *)c);

    if (event_add(&c->event, NULL) == -1) 
	{
        perror("event_add");
        return NULL;
    }

	add_msghdr(c);

    return c;
}

/*
 * Sets a connection's current state in the state machine. Any special
 * processing that needs to happen on certain state transitions can
 * happen here.
 */
static void conn_set_state(conn_t *c, conn_states_e state) 
{
    if (state != c->state) 
	{
        c->state = state;
    }
}
static void conn_set_wstate(conn_t *c, conn_wstates_e state) 
{
    if (state != c->wstate) 
	{
        c->wstate = state;
    }
}
static void _mem_free(conn_t *c)
{
	int i = 0;
	if(c == NULL)
		return;
	
	for( i = 0 ; i < c->used_free_size ;i++)
	{
		if(c->mem_free[i])
		{
			free(c->mem_free[i]);
			c->mem_free[i] = NULL;
		}
	}
	c->used_free_size = 0;

	return;
}
static void clean_mem_free(conn_t *c)
{
	_mem_free(c);
	if(c->total_free_size)
		free(c->mem_free);
	c->total_free_size = 0;
	return;
}
static void conn_cleanup(conn_t *c) 
{
    if(c == NULL)
		return;

    if (c->transport == udp_transport) 
	{
        conn_set_state(c, conn_read);
    }
	clean_mem_free(c);
}

static void conn_close(conn_t *c) 
{
	int i = 0;
	
    if(c == NULL)
		return;

    /* delete the event, the socket and the conn */
    if(c->state != conn_drain)
        event_del(&c->event);
	if(c->wstate == conn_mwrite)
		event_del(&c->wevent);
	/*clear time event*/
	for(i = 0 ; i < TIMER_EVENT_NUM ; i++)
	{
		if(c->timeevent[i] != NULL)
		{
			event_del(c->timeevent[i]);
			event_free(c->timeevent[i]);
			c->timeevent[i] = NULL;
		}
	}

	/*if any*/
	c->user_data = NULL ; 
    conn_cleanup(c);

    conn_set_state(c, conn_closed);
	conn_set_wstate(c, conn_wclosed);
    close(c->sfd);
	remove_thread_conn(c->thread,c);

    return;
}


/*
 * Dispatches a new connection to another thread. This is only ever called
 * from the main thread, either during initialization (for UDP) or because
 * of an incoming connection.
 */
void dispatch_conn_new(int sfd, conn_states_e init_state, int event_flags,
                       int read_buffer_size, network_transport_e transport) {

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

    event_thread_t *thread = threads + tid;

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
	int avail = c->rsize - c->rbytes;
    c->request_addr_size = sizeof(c->request_addr);
    ret = recvfrom(c->sfd, c->rbuf + c->rbytes , avail,
                   0, (struct sockaddr *)&c->request_addr,
                   &c->request_addr_size);

	if(ret > 0)
	{
		c->rbytes += ret;	
		return READ_SOME_DATA;
	}
	else
	{
		return READ_NONE;
	}
	return READ_NONE;
}
read_status_e try_read_network(conn_t *c) 
{
    read_status_e gotdata = READ_NONE;
    int res;
    

    while (1) 
	{
        if (c->rbytes >= c->rsize) 
		{
			int new_size = 0;
			if(c->rsize >= g_setting.max_user_rbuf)
			{
				return READ_SOME_DATA;
			}
			if(c->rsize * 2 >= g_setting.max_user_rbuf)
				new_size = g_setting.max_user_rbuf;
			else
				new_size = c->rsize * 2;
            char *new_rbuf = realloc(c->rbuf, new_size);
            if (!new_rbuf) 
			{
				c->thread->stats->malloc_fails++;
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
				return gotdata;
            }
            return READ_ERROR;
        }
    }
	
    return gotdata;
}


/*
 * Adds a message header to a connection.
 *
 * Returns 0 on success, -1 on out-of-memory.
 */
static int add_msghdr(conn_t *c)
{
    struct msghdr *msg;

    if(c == NULL)
    {
    	return -1;
    }

    msg = &(c->msglist[ (c->msgcurr + c->msgused) % c->msgsize]);

    /* this wipes msg_iovlen, msg_control, msg_controllen, and
       msg_flags, the last 3 of which aren't defined on solaris: */
    memset(msg, 0, sizeof(struct msghdr));

    msg->msg_iov = &c->iov[(c->iovcurr + c->iovused) % c->iovsize];

    if (c->transport == udp_transport && c->request_addr_size > 0) 
	{
        msg->msg_name = &c->request_addr;
        msg->msg_namelen = c->request_addr_size;
    }

    c->msgbytes = 0;
	c->msgused += 1;
    return 0;
}
void print_s(char * pre,conn_t *c)
{
	printf("%s[size:%d used:%d cur:%d bytes:%d]  [iovsize:%d iovused:%d iovcur:%d]\n",
		pre,c->msgsize,c->msgused,c->msgcurr,c->msgbytes,
		c->iovsize,c->iovused,c->iovcurr);

	return;
}
int  conn_msg_reset(conn_t *c)
{
	int ret = 0;
	if(c == NULL) return -1;

	
	c->iovcurr = 0;
	c->iovused = 0;
    c->msgcurr = 0;
    c->msgused = 0;
	c->msgbytes = 0;

	return add_msghdr(c);
	
}

int eventbase_add_write_data(conn_t *c, const void *buf, int len,int need_free) ;
/**
 * copy data to user write buffer 
 * 
 * @note: 
 *		using copy method
 *
 * @param[in] c	  		:client structure
 * @param[in] buf	  	:data buffer addr
 * @param[in] len	  	:data length
 *
 * @return: 0 if success . -1 if error
 */
int eventbase_copy_write_data(conn_t *c , void *buf, int len)
{
	int ret ;
	if(!c || !buf || len <= 0 || len > c->wsize - c->wbytes)
		return -1;

	int re_pos = (c->wcurr - c->wbuf + c->wbytes) % c->wsize;
	if( re_pos + len > c->wsize)
	{
		memmove( c->wbuf + re_pos,buf,c->wsize - re_pos);
		ret = eventbase_add_write_data(c,c->wbuf + re_pos, c->wsize - re_pos,0) ;
		if(ret < 0)
			goto FAIL;

		memmove(c->wbuf,buf + c->wsize - re_pos ,len - (c->wsize - re_pos) );
		ret = eventbase_add_write_data(c,c->wbuf, len - (c->wsize - re_pos),0) ;
		if(ret < 0)
			goto FAIL;
		
	}else
	{
		memmove( c->wbuf + re_pos,buf,len);
		ret = eventbase_add_write_data(c,c->wbuf + re_pos, len,0) ;
		if(ret < 0)
			goto FAIL;
	}
	c->wbytes += len;
	return 0;

FAIL:
	c->wbytes += len;
	return -1;	
}
int cal_mdata_len(conn_t * c)
{
	int len = 0 , i = 0;
	int used = c->msgused;
	int cur = c->msgcurr;

	if (c->msgused > 0 && c->msglist[cur].msg_iovlen > 0) 
	{
		while(used)
		{
			for(i = 0 ; i < c->msglist[cur].msg_iovlen ; i++)
			{
				len += c->msglist[cur].msg_iov[i].iov_len;
			}
			cur = ( ++cur) % c->msgsize ;
			used--;
		}
	}else
		return 0;

	return len;
}
/**
 * add data to user write buffer 
 * 
 * @note: 
 *		no copy method. we just register [buf,len] in our conn_t.so don't release them 
 *
 * @param[in] c	  		:client structure
 * @param[in] buf	  	:data buffer addr
 * @param[in] len	  	:data length
 * @param[in] need_free	:buf need free after send out
 *
 * @return: 0 if success . -1 if error
 */
int eventbase_add_write_data(conn_t *c, const void *buf, int len,int need_free) 
{
	int ret ;
    struct msghdr *m;
    int leftover;

	if(buf == NULL || len <= 0 )
		return -1;

	if(c->msgused >= c->msgsize)
		return -1;
	if(c->iovused >= c->iovsize)
		return -1;
	
	if(cal_mdata_len(c) + len > g_setting.max_data_sending)
	{
		return -1;
	}
	
    if (c->transport == udp_transport) 
	{
        do {
            m = &c->msglist[(c->msgcurr + c->msgused - 1) % c->msgsize];

            /*
             * Limit UDP packets to UDP_MAX_PAYLOAD_SIZE bytes.
             */

            /* We may need to start a new msghdr if this one is full. */
            if (m->msg_iovlen == IOV_MAX ||
                (c->msgbytes >= UDP_MAX_PAYLOAD_SIZE) ||
                 c->iovcurr + c->iovused == c->iovsize) //iov can not wrap in an msghdr
           	{
                ret = add_msghdr(c);
				if(ret < 0)
					return -1;
                m = &c->msglist[(c->msgcurr + c->msgused -1 ) % c->msgsize];
            }

            /* If the fragment is too big to fit in the datagram, split it up */
            if (len + c->msgbytes > UDP_MAX_PAYLOAD_SIZE) 
			{
                leftover = len + c->msgbytes - UDP_MAX_PAYLOAD_SIZE;
                len -= leftover;
            } else 
			{
                leftover = 0;
            }

            m = &c->msglist[(c->msgcurr + c->msgused - 1) % c->msgsize];
            m->msg_iov[m->msg_iovlen].iov_base = (void *)buf;
            m->msg_iov[m->msg_iovlen].iov_len = len;

            c->msgbytes += len;
            m->msg_iovlen++;
			c->iovused++;
			
            buf = ((char *)buf) + len;
            len = leftover;
        } while (leftover > 0);

    } else 
	{
		
        /* Optimized path for TCP connections */
        m = &c->msglist[ (c->msgcurr + c->msgused - 1) % c->msgsize ];
        if (m->msg_iovlen == IOV_MAX || c->iovcurr + c->iovused == c->iovsize) 
		{
            ret = add_msghdr(c);
			if(ret < 0)
				return -1;
            m = &c->msglist[(c->msgcurr + c->msgused - 1) % c->msgsize ];
        }

        m->msg_iov[m->msg_iovlen].iov_base = (void *)buf;
        m->msg_iov[m->msg_iovlen].iov_len = len;
        c->msgbytes += len;
        c->iovused++;
        m->msg_iovlen++;
		
    }

	if(need_free)
	{
		if(c->used_free_size >= c->total_free_size)
		{
			if(c->total_free_size == 0)
			{
				c->mem_free = (void **)calloc(c->total_free_size + 5 , sizeof(char *));
			}else
			{
				c->mem_free = (void **)realloc(c->mem_free , (c->total_free_size + 5) * sizeof(char *) );
			}
			if(c->mem_free == NULL)
				return -1;
			c->total_free_size += 5;
		}
		c->mem_free[c->used_free_size] = (void *)buf;
		c->used_free_size++;
	}
	//print_s("add",c);
    return 0;
}

transmit_result_e try_send_data(conn_t *c) 
{
	int ret = 0;
	int send_num = 0;
	int data_line_num, data_line2_num;
	int re_line = (c->wcurr - c->wbuf + c->wbytes) / c->wsize ;
	int re_pos = (c->wcurr - c->wbuf + c->wbytes) % c->wsize ;

	if(c->wbytes <= 0) return TRANSMIT_COMPLETE;
	if(re_line )
	{
		data_line_num = c->wsize - (c->wcurr - c->wbuf) ;
		data_line2_num = re_pos;
	}else
	{
		data_line_num = c->wbytes;
		data_line2_num = 0;
	}

	if(data_line_num)
	{
		if(c->transport == udp_transport)
		{
			int sum = 0;
			int packet = data_line_num;
			while(sum < data_line_num)
			{
				if(packet > UDP_MAX_PAYLOAD_SIZE)
					packet = UDP_MAX_PAYLOAD_SIZE;
				ret = sendto(c->sfd,c->wcurr + sum,packet,0,(struct sockaddr *)&(c->request_addr),c->request_addr_size);
				if(ret <= 0)
					return TRANSMIT_ERROR;
				sum += ret ;
				packet =  data_line_num - sum;
			}
			/*udp mode always*/
			ret = data_line_num;
			
		}else
		{
			ret = send(c->sfd,c->wcurr,data_line_num,0);
		}
		if(ret < 0 && (errno == EWOULDBLOCK || errno == EAGAIN))
		{
			return TRANSMIT_COMPLETE;
		}else if(ret > 0)
		{
			c->wcurr = c->wbuf + (c->wcurr - c->wbuf + ret) % c->wsize ;
			c->wbytes -= ret ;
			if(ret != data_line_num)
			{
				return TRANSMIT_COMPLETE;
			}
		}else
		{
			return TRANSMIT_ERROR;
		}
	}
	if(data_line2_num)
	{
		c->wcurr = c->wbuf;
		if(c->transport == udp_transport)
		{
			int sum = 0;
			int packet = data_line2_num;
			while(sum < data_line2_num)
			{
				if(packet > UDP_MAX_PAYLOAD_SIZE)
					packet = UDP_MAX_PAYLOAD_SIZE;
				ret = sendto(c->sfd,c->wcurr + sum,packet,0,(struct sockaddr *)&(c->request_addr),c->request_addr_size);
				if(ret <= 0)
					return TRANSMIT_ERROR;
				sum += ret ;
				packet =  data_line2_num - sum;
			}
			/*udp mode always*/
			ret = data_line2_num;
			
		}else
		{
			ret = send(c->sfd,c->wcurr,data_line2_num,0);
		}
		if(ret < 0 && (errno == EWOULDBLOCK || errno == EAGAIN))
		{
			return TRANSMIT_COMPLETE;
		}else if(ret > 0)
		{
			c->wcurr = c->wbuf + (c->wcurr - c->wbuf + ret) % c->wsize ;
			c->wbytes -= ret ;
			if(ret != data_line2_num)
			{
				return TRANSMIT_COMPLETE;
			}
		}else
		{
			return TRANSMIT_ERROR;
		}
	}

	return TRANSMIT_COMPLETE;
}
void _release_space_wbuf_if_any(conn_t * c,char *buf ,int len)
{
	if(buf && len > 0 && buf >= c->wbuf && buf < c->wbuf + g_setting.user_copy_wbuf)
	{
		c->wcurr = c->wbuf + (c->wcurr - c->wbuf + len) % c->wsize ;
		c->wbytes -= len ;
	}

	return;
}

transmit_result_e try_send_mdata(conn_t *c) 
{
	int in_send_mdata = 0;
	
 	while(1)
 	{
	    if (c->msgused > 0 && c->msglist[c->msgcurr].msg_iovlen > 0) 
		{
			int i = 0;
	        ssize_t res;
	        struct msghdr *m = &c->msglist[c->msgcurr];

			in_send_mdata = 1;
	        res = sendmsg(c->sfd, m, 0);
			
	        if (res > 0) 
			{
				//print_s("before sendmsg", c);
				c->msgbytes -= res;
	            /* We've written some of the data. Remove the completed
	               iovec entries from the list of pending writes. */
	            while (m->msg_iovlen > 0 && res >= m->msg_iov->iov_len) 
				{
					_release_space_wbuf_if_any(c,m->msg_iov->iov_base,m->msg_iov->iov_len);
	                res -= m->msg_iov->iov_len;
	                m->msg_iovlen--;
	                m->msg_iov++;
					if(m->msg_iov >= c->iov + c->iovsize)  m->msg_iov = c->iov;
					c->iovused--;
					c->iovcurr = ( ++c->iovcurr ) % c->iovsize ;
	            }
				//print_s("before sendmsg", c);
				
	            /* Might have written just part of the last iovec entry;
	               adjust it so the next write will do the rest. */
	            if (res > 0) 
				{
					_release_space_wbuf_if_any(c,(caddr_t)m->msg_iov->iov_base,res);
	                m->msg_iov->iov_base = (caddr_t)m->msg_iov->iov_base + res;
	                m->msg_iov->iov_len -= res;
					return TRANSMIT_INCOMPLETE;
	            }
				c->msgcurr = ( ++c->msgcurr) % c->msgsize ;
				c->msgused--;
				//print_s("after sendmsg", c);
				c->msgbytes = 0;
				for(i = 0 ; i < c->msglist[c->msgcurr].msg_iovlen ; i++)
				{
					c->msgbytes += c->msglist[c->msgcurr].msg_iov[i].iov_len;
				}
				continue;
	        }
	        if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) 
			{
	            return TRANSMIT_INCOMPLETE;
	        }
	        /* if res == 0 or res == -1 and error is not EAGAIN or EWOULDBLOCK,
	           we have a real error, on which we close the connection */

	        return TRANSMIT_ERROR;
	    } else 
		{
			if(in_send_mdata > 0)
			{
				c->msgcurr--;
				c->msgused++;
				if(c->msgcurr < 0) c->msgcurr = c->msgsize - 1;
			}
	        return TRANSMIT_COMPLETE;
	    }
		c->msgcurr = ( ++c->msgcurr ) % c->msgsize;
 	}
	
}

void eventbase_add_wevent(conn_t *c)
{
	if(c->wstate == conn_mwrite)
		return;

	if(c->msglist[c->msgcurr].msg_iovlen > 0)
		c->wstate = conn_mwrite;
	else
		return;

	event_assign(&c->wevent, c->thread->base, c->sfd, EV_WRITE | EV_PERSIST , 
		event_whandler, c);
	event_add(&c->wevent,NULL);
}
void eventbase_delete_wevent(conn_t *c)
{
	if(c->wstate != conn_mwrite)
		return;
	
	
	switch(c->wstate)
	{
		case conn_mwrite:
			c->wstate = conn_nowrite;
			event_del(&c->wevent);
			break;

	}
	
	return;
}

void drive_machine(conn_t *c)
{
	int stop = false;
	int sfd;
	int parse_len = 0;
	socklen_t addrlen;
	read_status_e read_ret;
	parse_status_f parse_ret ;
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
	                
	                if (errno == EAGAIN || errno == EWOULDBLOCK) 
					{
	                    /* these are transient, so don't log anything */
	                    stop = true;
	                } else if (errno == EMFILE) 
	                {
	                	server_stats.maxconns_last_occur = current_time;
						server_stats.maxconns_times++;
	                	/*too many open fds*/
	                    stop = true;
	                } else 
					{
	                    stop = true;
	                }
	                break;
	            }
	           	
				anetNonBlock(NULL, sfd);
				anetSndbuf(sfd,g_setting.socket_wbuf);

	            if (sfd >= g_setting.max_connections - 1) 
	           	{
	                close(sfd);
					stop = true;
	            } else 
				{
	                dispatch_conn_new(sfd, conn_read, EV_READ | EV_PERSIST,
	                                     DATA_BUFFER_SIZE, c->transport);
	            }
	            
				break;
				
			case conn_read:
				
				c->last_cmd_time = current_time;
				if(c->transport == udp_transport)
					read_ret = try_read_udp(c);
				else
					read_ret = try_read_network(c);
				c->read_state = read_ret;
				switch (read_ret) 
				{
		            case READ_NONE:
						stop = true;
		                break;
		            case READ_DATA_DONE:
					case READ_SOME_DATA:
		                conn_set_state(c, conn_parse_cmd);
		                break;
		            case READ_ERROR:
		                conn_set_state(c, conn_closing);
		                break;
	            }
				
				break;
			case conn_parse_cmd:
				
				c->last_cmd_time = current_time;
				parse_len = 0;
				parse_ret = protocol_parse(c,c->rcurr,c->rbytes,&parse_len);
				if(parse_len < 0 || parse_len > c->rsize)
				{/*value parse_len illegal*/
					conn_set_state(c, conn_closing);
					break;
				}
				if(parse_ret & PARSE_ERROR)
				{
                    if(parse_ret & PARSE_NEED_WRITE)
                    {
                        event_del(&c->event);
					    conn_set_state(c, conn_drain);
					    eventbase_add_wevent(c);
                        stop = true;
                    }else
                    {
					    conn_set_state(c, conn_closing);
                    }
					break;
				}
				if(c->rbytes >= c->rsize && parse_len == 0)
				{
					conn_set_state(c, conn_closing);
					break;
				}
				if(parse_ret & PARSE_NEED_WRITE)
					eventbase_add_wevent(c);
				if(parse_ret & PARSE_DONE)
				{
					conn_set_state(c, conn_read);
					/*no data in user read buffer*/
					if(c->read_state != READ_SOME_DATA)	
						stop = true;

					if(c->transport == udp_transport)
					{
						c->rcurr = c->rbuf;
						c->rbytes = 0;
						
					}else if(c->transport == tcp_transport)
					{
						c->rbytes -= parse_len;
						c->rcurr += parse_len;
						if (c->rcurr != c->rbuf) 
						{
					        if (c->rbytes != 0) /* otherwise there's nothing to copy */
					            memmove(c->rbuf, c->rcurr, c->rbytes);
					        c->rcurr = c->rbuf;
					    }
					}
				}

				break;

			case conn_closing:
				c->thread->stats->curr_clients--;
				if (c->transport == udp_transport)
	                conn_cleanup(c);
	            else
	                conn_close(c);
	            stop = true;
	            break;
			case conn_closed:
	            /* This only happens if dormando is an idiot. */
	            abort();
	            break;
        	case conn_max_state:
            	break;
		}
	}


	return;
}
void write_machine(conn_t *c)
{
	int ret;
	int stop = false;

	while(stop == false)
	{
		switch(c->wstate)
		{/*
			case conn_write:
				c->last_cmd_time = current_time;
				switch (try_send_data(c)) 
				{
					case TRANSMIT_COMPLETE:
						eventbase_delete_wevent(c);
                        if(c->state == conn_drain)
                        {
                            conn_set_wstate(c,conn_wclosing);
                        }else
                        {
						    stop = true;
                        }
						break;

					case TRANSMIT_INCOMPLETE:
						stop = true;
						break;
					case TRANSMIT_ERROR:
						if(c->transport == udp_transport)
						{
							eventbase_delete_wevent(c);
						}else
						{
							conn_set_wstate(c, conn_wclosing);
						}
				}
				break;*/
				
			case conn_mwrite:
				
				c->last_cmd_time = current_time;
				switch (try_send_mdata(c)) 
				{
					case TRANSMIT_COMPLETE:
						eventbase_delete_wevent(c);
						_mem_free(c);
                        if(c->state == conn_drain)
                        {
                            conn_set_wstate(c,conn_wclosing);
                        }else
                        {
						    stop = true;
                        }
						break;

					case TRANSMIT_INCOMPLETE:
							stop = true;
							break;
						
					case TRANSMIT_ERROR:
						if(c->transport == udp_transport)
						{
							eventbase_delete_wevent(c);
						}else
						{
							conn_set_wstate(c, conn_wclosing);
						}
				}
				
				//print_s(c);
				break;
			case conn_wclosing:
				c->thread->stats->curr_clients--;
				if (c->transport == udp_transport)
		            conn_cleanup(c);
		        else
		            conn_close(c);
		        stop = true;
		        break;
		}
	}
}
void event_whandler(const int fd, const short which, void *arg) 
{
	conn_t *c;

    c = (conn_t *)arg;


    /* sanity */
    if (fd != c->sfd) 
	{
        conn_close(c);
        return;
    }

    write_machine(c);
	
    /* wait for next event */
    return;
}

void event_handler(const int fd, const short which, void *arg) 
{
    conn_t *c;

    c = (conn_t *)arg;


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

static void thread_live_process(int fd, short which, void *arg) 
{
	event_thread_t *me = arg;
	int count = 0;
	conn_t * next;
	conn_t * c ;

	for(c = me->conn_list ; c  ;)
	{
		next = c->next;

		if(current_time - c->last_cmd_time > g_setting.max_mute_time)
		{
			conn_close(c);
		}
		c = next;
	}

	return;
}
/*
 * Processes an incoming "handle a new connection" item. This is called when
 * input arrives on the libevent wakeup pipe.
 */
static void thread_libevent_process(int fd, short which, void *arg) 
{
    event_thread_t *me = arg;
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
					add_thread_conn(me,c);
					c->thread->stats->total_clients++;
					c->thread->stats->curr_clients++;
		        }
				
		        cqi_free(item);
		        break;
	    }
    }
}

static void setup_thread(event_thread_t *me) 
{
    me->base = event_base_new();
	struct timeval _sec={.tv_sec=60,.tv_usec=0};

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
	if(g_setting.max_mute_time > 0)
	{
		event_assign(&me->live_event,me->base, -1,EV_PERSIST, thread_live_process, me);
		if (event_add(&me->live_event, &_sec) == -1) 
		{
			fprintf(stderr, "Can't monitor libevent live event\n");
			exit(1);
		}
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
    event_thread_t *me = arg;

	sprintf(thread_name,"event_%d",(int)(me - threads + 1));
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

    if ((ret = pthread_create(&((event_thread_t*)arg)->thread_id, &attr, func, arg)) != 0) 
	{
        perror("Can't create thread");
        exit(1);
    }

	return;
}

/* libevent uses a monotonic clock when available for event scheduling. Aside
 * from jitter, simply ticking our internal timer here is accurate enough.
 * Note that users who are setting explicit dates for expiration times *must*
 * ensure their clocks are correct before starting memcached. */
static void clock_handler(const int fd, const short which, void *arg) 
{
    struct timeval t = {.tv_sec = 1, .tv_usec = 0};
	struct timespec ts;
    static int initialized = false;
    static time_t monotonic_start;


    if (initialized) 
	{
		//printf("clock_handler %d\n",current_time);
    } else 
	{
		if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
        	return;
		monotonic_start = ts.tv_sec;
		event_assign(&clockevent,(struct event_base *)arg,-1,EV_PERSIST, clock_handler, 0);
    	event_add(&clockevent, &t);
		initialized = true;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
        return;
    current_time = (unsigned int)ts.tv_sec - monotonic_start;
    return;
    
}

/**
 * delete time event to thread loop
 * 
 * @note: 
 *		
 *
 * @param[in] c	 		:client structure
 * @param[in] _arg     	:timeevent identifier
 *
 * @return:  0 if success .-1 if error
 */
int eventbase_delete_time_event(conn_t *c,timeevent_handle _arg      )
{
	if(_arg < 0 || _arg >= TIMER_EVENT_NUM || c == NULL)
		return -1;

	if(c->timeevent[_arg] == NULL)
		return 0;

	event_del(c->timeevent[_arg]);
	event_free(c->timeevent[_arg]);
	c->timeevent[_arg] = NULL;

	return 0;
}
/**
 * add time event to thread loop
 * 
 * @note: 
 *		this makes event persistent until eventbase_delete_time_event() is called.
 *
 * @param[in] c	 		:client structure
 * @param[in] millionsec     :the time to wait for callback fires
 * @param[in] func     	:callback
 *
 * @return: identifier for a certain event,which is in range [0 ... ... TIMER_EVENT_NUM - 1] .
 *			-1 if error
 */
timeevent_handle eventbase_add_time_event(conn_t *c, int millionsec,_event_callback func)
{
	int i = 0 ;
	struct timeval _sec;

	if(c == NULL) return -1;
	for(i = 0 ; i < TIMER_EVENT_NUM ; i++)
	{
		if(c->timeevent[i] == NULL)
			break;
	}
	/*only TIMER_EVENT_NUM time events we can add*/
	if(i >= TIMER_EVENT_NUM)
		return -1;

	_sec.tv_sec = millionsec / 1000 ;
	_sec.tv_usec = millionsec % 1000 * 1000 ;
	c->timeevent[i] = event_new(c->thread->base,-1,EV_PERSIST,func,c);

	event_add(c->timeevent[i],&_sec);
	
	return i;
}

/**
 * print server stats into buf in json format
 * 
 * @note: 
 *		i do not know the situation when length is too small 
 *
 * @param[in] buf	 :buffer prealloced
 * @param[in] length     :the length of buffer
 * 
 * @return: 0 if success. -1 if error
 */
int eventbase_get_stats(char *buf,int length)
{
	int i , ret;
	cJSON *root = NULL;
	cJSON *thread = NULL;
	cJSON *fld = NULL;

	if(buf == NULL || length <= 0)
		return -1;
	root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root,"maxconns_times",server_stats.maxconns_times);
	cJSON_AddNumberToObject(root,"maxconns_last_occur",server_stats.maxconns_last_occur);
	cJSON_AddItemToObject(root, "thread", thread = cJSON_CreateArray());
	
	for(i = 0 ; i < g_setting.num_work_threads ; i++)
	{	
		cJSON_AddItemToArray(thread, fld = cJSON_CreateObject());
		cJSON_AddNumberToObject(fld,"total_clients",server_stats.thread_stat[i].total_clients);
		cJSON_AddNumberToObject(fld,"curr_clients",server_stats.thread_stat[i].curr_clients);
		cJSON_AddNumberToObject(fld,"malloc_fails",server_stats.thread_stat[i].malloc_fails);
	}

	ret = cJSON_PrintPreallocated(root,buf,length,1);

	cJSON_Delete(root);

	return ret == 1?0:-1;
}
/**
 * init structure realated to thread pool .and create the pool
 * 
 * @note: 
 *		process may exit if fatal error we think
 *
 * @param[in] nthreads	  :number of threads
 *
 * @return: void
 */
void eventbase_thread_init(int nthreads) 
{
    int         i;
	int 		ret ;
    int         power;

    threads = calloc(nthreads, sizeof(event_thread_t));
	server_stats.thread_stat = calloc(nthreads, sizeof(thread_stat_t));
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
		threads[i].stats = &server_stats.thread_stat[i];
        setup_thread(&threads[i]);
    }

    /* Create threads after we've done all the libevent setup. */
    for (i = 0; i < nthreads; i++) 
	{
        create_worker(worker_libevent, &threads[i]);
    }

	return;
}

/**
 *  init data structure needed
 * 
 * @note: 
 *
 *
 * @param[in] void
 *
 * @return: 0 if success
 */
int eventbase_data_init(struct event_base * main_base)
{

	conn_init();
	
	clock_handler(0,0, main_base) ;

	return 0;
}

/**
 * init tcp and udp server listen socket.
 * and dispatch to certain loop
 * 
 * @note: 
 *
 *
 * @param[in] port	  		:server port
 * @param[in] main_base	  	:libevent base structure
 *
 * @return: 0 if success . -1 if error
 */
int eventbase_server_socket(int port,struct event_base *main_base)
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
	anetNonBlock(NULL, udp_fd);

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

