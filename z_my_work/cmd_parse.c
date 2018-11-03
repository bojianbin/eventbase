/*************************************************************************
	> File Name: cmd_parse.c
	> Author: 
	> Mail: 
	> Created Time: Thu 01 Nov 2018 10:27:31 AM CST
 ************************************************************************/

#include <stdio.h>
#include <string.h>

#include "cmd_parse.h"



void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen);


/**
 * protocol parse .fill write buffer and give feedback 
 * 
 * @note: 
 *		now may have three ways to write data to socket write buffer
 *     	1:int eventbase_copy_write_date(conn_t *c , void *buf, int len);
 *		2:int eventbase_add_write_data(conn_t *c, const void *buf, int len); 
 *		3:handle wbuf,wcurr,wsize,wbytes directly.this can reduse cpu load in some case
 *		4:change logical model. existing code can not cover all case.espacially mix use method 1 and 2 can 
 *			cause some problem. this may be fixed later.
 *
 * @param[in] c				:user main structure
 * @param[in] readbuf		:readbuffer filled with unparsed data
 * @param[in] totallen		:the unparsed readbuffer length
 * @param[out] totallen		:readbuf size we parsed this time
 *
 * @return:
 *			PARSE_DONE: 
 				we just parse.no need to write.@parsed_len give length we pass through.
 *			PARSE_DONE_NEED_WRITE:
 				we just parse.need to write.@parsed_len give length we pass through.
 *			PARSE_ERROR:
 				some fatal error occurs,need to close this client.
 */
parse_status_e protocol_parse(conn_t * c,char *readbuf,int totallen,int *parsed_len)
{
	char *str_find = "hello\r\n";
	char *ret_world = "world\r\n";
	char *ptr = readbuf;
	char *ret ;
	parse_status_e retvalue = PARSE_DONE;

	if(readbuf == NULL || totallen <= 0)
		goto END;
	while( ptr < readbuf + totallen && 
		(ret = memmem(ptr,totallen - (ptr-readbuf),str_find,strlen(str_find)) ) != 0)
	{
		eventbase_copy_write_date(c, ret_world,strlen(ret_world) );
		ptr = ret + strlen(str_find);
		retvalue = PARSE_DONE_NEED_WRITE;
	}
	
	*parsed_len = ptr - readbuf;

END:
	return retvalue;
}

void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
{
    int needle_first;
    const void *p = haystack;
    size_t plen = hlen;

    if (!nlen)
        return NULL;

    needle_first = *(unsigned char *)needle;

    while (plen >= nlen && (p = memchr(p, needle_first, plen - nlen + 1)))
    {
        if (!memcmp(p, needle, nlen))
            return (void *)p;

        p++;
        plen = hlen - (p - haystack);
    }

    return NULL;
}

