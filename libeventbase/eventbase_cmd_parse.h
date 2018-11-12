/*************************************************************************
	> File Name: cmd_parse.h
	> Author: 
	> Mail: 
	> Created Time: Thu 01 Nov 2018 10:27:36 AM CST
 ************************************************************************/

#ifndef _EVENTBASE_CMD_PARSE_H
#define _EVENTBASE_CMD_PARSE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "eventbase_threads.h"


/*data parse result. flag set*/
#define PARSE_DONE 1
#define PARSE_NEED_WRITE (1<<1)
#define PARSE_ERROR (1<<2)
typedef int parse_status_f;

/**
 * protocol parse.fill write buffer and give feedback 
 * 
 * @note: 
 *		now may have three ways to write data to socket write buffer
 *     	1:int eventbase_copy_write_date(conn_t *c , void *buf, int len);
 *		2:int eventbase_add_write_data(conn_t *c, const void *buf, int len); 
 *		3:handle wbuf,wsize,wbytes directly.this can reduce cpu load in some case
 *		
 *		1 and 3 belong to one send sequence system,which is different from 2.
 * 		we check and send 1,3 sequence first when no-write state become write state
 *		we can only ensure the order of transmission in same sequence system.so avoid mix use two sequence system
 *		without additional control logic.
 *
 * @param[in] c				:user main structure
 * @param[in] readbuf		:readbuffer filled with unparsed data
 * @param[in] totallen		:the unparsed readbuffer length
 * @param[out] parsed_len	:readbuf size we parsed this time
 *
 * @return:
 *			PARSE_DONE: 
 				we just parse.no need to write.@parsed_len give length we pass through.
 *			PARSE_NEED_WRITE:
 				we just parse.need to write.@parsed_len give length we pass through.
 *			PARSE_ERROR:
 				some fatal error occurs,need to close this client.
 */
parse_status_f protocol_parse(conn_t * c,char *readbuf,int totallen,int *parsed_len);




#ifdef __cplusplus
}
#endif

#endif
