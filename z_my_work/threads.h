/*************************************************************************
	> File Name: threads.h
	> Author: 
	> Mail: 
	> Created Time: Mon 29 Oct 2018 04:53:54 PM CST
 ************************************************************************/

#ifndef _THREADS_H
#define _THREADS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/socket.h>
#include "event2/event_struct.h"



#define ITEMS_PER_ALLOC 64

#define DATA_BUFFER_SIZE 2048

/** Initial size of the sendmsg() scatter/gather array. */
#define IOV_LIST_INITIAL 100
#define IOV_LIST_MAX 200
/** Initial number of sendmsg() argument structures to allocate. */
#define MSG_LIST_INITIAL 10
#define MSG_LIST_MAX 20

#define UDP_READ_BUFFER_SIZE 65536
#define UDP_MAX_PAYLOAD_SIZE 1400


#ifndef IOV_MAX
#define IOV_MAX 1024
#endif


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

typedef enum
{
    conn_listening,  /**< the socket which listens for connections */
    conn_read,       /**< reading in a command line */
    conn_parse_cmd,  /**< try to parse a command from the input buffer */
    conn_closing,    /**< closing this connection */
    conn_closed,     /**< connection is closed */
    conn_max_state   /**< Max state value (used for assertion) */
}conn_states_e;
typedef enum
{
	conn_nowrite,
    conn_write,      /**< writing out a simple response */
	conn_mwrite,     /**< writing out many items sequentially */
    conn_wclosing,    /**< closing this connection */
}conn_wstates_e;

typedef enum 
{
    TRANSMIT_COMPLETE,   /** All done writing. */
    TRANSMIT_INCOMPLETE, /** More data remaining to write. */
    //TRANSMIT_SOFT_ERROR, /** Can't write any more right now. */
    TRANSMIT_ERROR  /** Can't write (c->state is set to conn_closing) */
}transmit_result_e;


typedef enum  
{
    local_transport, /* Unix sockets*/
    tcp_transport,
    udp_transport
}network_transport_e;

struct conn_s;
typedef struct conn_queue_item_s
{
    int               		sfd;
    conn_states_e  		init_state;
    int               		event_flags;
    int               		read_buffer_size;
    network_transport_e  transport;
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
    conn_states_e  state;
	conn_wstates_e  wstate;
	read_status_e read_state;
    unsigned int last_cmd_time;
	/*event for read*/
    struct event event;
	/*event for write*/
	struct event wevent;
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


    network_transport_e transport; /* what transport is used by this connection */

    /* data for UDP clients */
    struct sockaddr_in6 request_addr; /* udp: Who sent the most recent request */
    socklen_t request_addr_size;
 
    struct conn_s   *next;     /* Used for generating a list of conn structures */
    EVENT_THREAD *thread; /* Pointer to the thread object serving this connection */

	void *user_data;
}conn_t;



int eventbase_data_init();
int server_socket_init(int port,struct event_base *main_base);
void eventbase_thread_init(int nthreads) ;

int eventbase_copy_write_date(conn_t *c , void *buf, int len);
int eventbase_add_write_data(conn_t *c, const void *buf, int len); 

#ifdef __cplusplus
}
#endif


#endif
