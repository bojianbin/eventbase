/*************************************************************************
	> File Name: cmd_parse.h
	> Author: 
	> Mail: 
	> Created Time: Tue 06 Nov 2018 10:04:04 AM CST
 ************************************************************************/

#ifndef _CMD_PARSE___H
#define _CMD_PARSE___H

#include "eventbase_cmd_parse.h"
#include "eventbase_threads.h"

typedef parse_status_f (*cmd_func)(conn_t *c,char *readbuf,int buf_len);

typedef struct
{
	char * key_words;
	cmd_func handle;	
}cmd_dict_t;



#endif
