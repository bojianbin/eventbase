/*************************************************************************
	> File Name: threads.h
	> Author: 
	> Mail: 
	> Created Time: Mon 29 Oct 2018 04:53:54 PM CST
 ************************************************************************/

#ifndef _THREADS_H
#define _THREADS_H

#include <sys/socket.h>
#include "event2/event_struct.h"



#define ITEMS_PER_ALLOC 64

#define DATA_BUFFER_SIZE 2048

/** Initial size of the sendmsg() scatter/gather array. */
#define IOV_LIST_INITIAL 400

/** Initial number of sendmsg() argument structures to allocate. */
#define MSG_LIST_INITIAL 10

#define UDP_READ_BUFFER_SIZE 65536

#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

typedef enum
{
	/*reads > 0 && may have remaining data to read*/
	READ_SOME_DATA,
	/*reads > 0 && no remaining data*/
	READ_DATA_DONE,
	/*reads < 0 && errno == EWOULDBLOCK*/
	READ_NONE,
	/*reads <= 0 && errno != EWOULDBLOCK && errno != EAGIN*/
	READ_ERROR
}read_status_e;

enum conn_states 
{
    conn_listening,  /**< the socket which listens for connections */
    conn_new_cmd,    /**< Prepare connection for next command */
    conn_waiting,    /**< waiting for a readable socket */
    conn_read,       /**< reading in a command line */
    conn_parse_cmd,  /**< try to parse a command from the input buffer */
    conn_write,      /**< writing out a simple response */
    conn_nread,      /**< reading in a fixed number of bytes */
    conn_swallow,    /**< swallowing unnecessary bytes w/o storing */
    conn_closing,    /**< closing this connection */
    conn_mwrite,     /**< writing out many items sequentially */
    conn_closed,     /**< connection is closed */
    conn_watch,      /**< held by the logger thread as a watcher */
    conn_max_state   /**< Max state value (used for assertion) */
};



enum network_transport 
{
    local_transport, /* Unix sockets*/
    tcp_transport,
    udp_transport
};

struct conn_s;
typedef struct conn_queue_item_s
{
    int               		sfd;
    enum conn_states  		init_state;
    int               		event_flags;
    int               		read_buffer_size;
    enum network_transport  transport;
    struct conn_s 					*c;
    struct conn_queue_item_s          		*next;
}conn_queue_item_t;

/* A connection queue. */
typedef struct conn_queue_s 
{
    conn_queue_item_t *head;
    conn_queue_item_t *tail;
    pthread_mutex_t lock;
}conn_queue_t;

typedef struct 
{
    pthread_t thread_id;        /* unique ID of this thread */
    struct event_base *base;    /* libevent handle this thread uses */
    struct event notify_event;  /* listen event for notify pipe */
    int notify_receive_fd;      /* receiving end of notify pipe */
    int notify_send_fd;         /* sending end of notify pipe */
    conn_queue_t *new_conn_queue; /* queue of new connections to handle */
	
} EVENT_THREAD;

typedef struct conn_s
{
    int    sfd;
    enum conn_states  state;
    unsigned int last_cmd_time;
    struct event event;
    short  ev_flags;
    short  which;   /** which events were just triggered */

    char   *rbuf;   /** buffer to read commands into */
    char   *rcurr;  /** but if we parsed some already, this is where we stopped */
    int    rsize;   /** total allocated size of rbuf */
    int    rbytes;  /** how much data, starting from rcur, do we have unparsed */

    char   *wbuf;
    char   *wcurr;
    int    wsize;
    int    wbytes;
    /** which state to go into after finishing current write */
    enum conn_states  write_and_go;
    void   *write_and_free; /** free this memory after finishing writing */


    /* data for the mwrite state */
    struct iovec *iov;
    int    iovsize;   /* number of elements allocated in iov[] */
    int    iovused;   /* number of elements used in iov[] */

    struct msghdr *msglist;
    int    msgsize;   /* number of elements allocated in msglist[] */
    int    msgused;   /* number of elements used in msglist[] */
    int    msgcurr;   /* element in msglist[] being transmitted now */
    int    msgbytes;  /* number of bytes in current msg */


    enum network_transport transport; /* what transport is used by this connection */

    /* data for UDP clients */
    struct sockaddr_in6 request_addr; /* udp: Who sent the most recent request */
    socklen_t request_addr_size;
 
    struct conn_s   *next;     /* Used for generating a list of conn structures */
    EVENT_THREAD *thread; /* Pointer to the thread object serving this connection */
}conn_t;



int eventbase_data_init();
int server_socket_init(int port,struct event_base *main_base);
void eventbase_thread_init(int nthreads) ;


#endif
