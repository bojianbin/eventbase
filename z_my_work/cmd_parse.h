/*************************************************************************
	> File Name: cmd_parse.h
	> Author: 
	> Mail: 
	> Created Time: Thu 01 Nov 2018 10:27:36 AM CST
 ************************************************************************/

#ifndef _CMD_PARSE_H
#define _CMD_PARSE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "threads.h"

typedef enum
{
	/*normal case.*/
	PARSE_DONE,
	PARSE_DONE_NEED_WRITE,
	/*fatal error .need close this client*/
	PARSE_ERROR
	
}parse_status_e;
parse_status_e protocol_parse(conn_t * c,int *parsed_len);




#ifdef __cplusplus
}
#endif

#endif
