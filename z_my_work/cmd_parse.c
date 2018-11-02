/*************************************************************************
	> File Name: cmd_parse.c
	> Author: 
	> Mail: 
	> Created Time: Thu 01 Nov 2018 10:27:31 AM CST
 ************************************************************************/

#include<stdio.h>

#include"cmd_parse.h"

parse_status_e protocol_parse(conn_t * c,int *parsed_len)
{


	parsed_len = 0;
DONE:
	return PARSE_DONE;
DONE_WRITE:
	return PARSE_DONE_NEED_WRITE;
ERR:
	return PARSE_ERROR;
}


