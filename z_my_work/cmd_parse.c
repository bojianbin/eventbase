/*************************************************************************
	> File Name: cmd_parse.c
	> Author: 
	> Mail: 
	> Created Time: Thu 01 Nov 2018 10:27:31 AM CST
 ************************************************************************/
/*
* a simple demo with libeventbase
* protocol:
*		hello\r\n\r\n    	server return string :world
*		stat\r\n\r\n		server return one json string about server status
*		string n\r\n\r\n	server return one n length string
*
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>

#include "eventbase_cmd_parse.h"
#include "cmd_parse.h"


char *ret_world = "world";
parse_status_f hello_func(conn_t * c,char *_buf,int len)
{
	eventbase_add_write_data(c, ret_world,strlen(ret_world) );

	return (PARSE_NEED_WRITE | PARSE_DONE);
}
parse_status_f stat_func(conn_t * c,char *_buf,int len)
{
	char *buf  = (char *)calloc(1,2048);

	eventbase_get_stats(buf, 2048);
	eventbase_copy_write_data(c,buf,strlen(buf));

	free(buf);
	return (PARSE_NEED_WRITE | PARSE_DONE);
}
parse_status_f string_func(conn_t * c,char *_buf,int len)
{
	static char *str_sore = "abcdefghijklmnopqrstuvwxyz";
	char * ptr = _buf + strlen("string");
	int str_len = 0;
	int ret ,line_len;


	ret = sscanf(ptr,"%d",&str_len);
	//printf("%d %d\n",ret , str_len);
	if(ret <= 0)
		return PARSE_ERROR;

	while(str_len / strlen(str_sore) >= 1)
	{
		eventbase_add_write_data(c, str_sore,strlen(str_sore) );
		str_len -=  strlen(str_sore);
	}
	if(str_len > 0)
	{
		eventbase_add_write_data(c, str_sore,str_len );
	}

	return PARSE_DONE | PARSE_NEED_WRITE ;
	
}

cmd_dict_t cmd_dict[] = 
{
	{"hello",hello_func},			/*hello\r\n\r\n*/
	{"stat",stat_func},				/*stat\r\n\r\n*/
	{"string",string_func}			/*string n\r\n\r\n*/
};

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


/**
 * protocol parse .fill write buffer and give feedback 
 * 
 * @note: 
 *		now may have three ways to write data to socket write buffer
 *     	1:int eventbase_copy_write_date(conn_t *c , void *buf, int len);
 *		2:int eventbase_add_write_data(conn_t *c, const void *buf, int len); 
 *		3:handle wbuf,wcurr,wsize,wbytes directly.this can reduse cpu load in some case
 *		
 *		may need change logical model. existing code can not cover all case.espacially mix use method 1 and 2 can 
 *		cause some problem. this may be fixed later.
 *
 * @param[in] c				:user main structure
 * @param[in] readbuf		:readbuffer filled with unparsed data
 * @param[in] totallen		:the unparsed readbuffer length
 * @param[out] parsed_len	:readbuf size we parsed this time
 *
 * @return:
 *			PARSE_DONE: 
 				we just parse.no need to write.@parsed_len give length we pass through.
 *			PARSE_DONE_NEED_WRITE:
 				we just parse.need to write.@parsed_len give length we pass through.
 *			PARSE_ERROR:
 				some fatal error occurs,need to close this client.
 */
parse_status_f protocol_parse(conn_t * c,char *readbuf,int totallen,int *parsed_len)
{
	int find_one = 0;
	char *ptr = readbuf;
	int i,ret;
	parse_status_f retvalue = PARSE_DONE;
	char *end_pos = NULL;

	*parsed_len = 0;
	if(readbuf == NULL || totallen <= 0)
		goto END;

	//printf("totallen:%d\n",totallen);
	while( ptr < readbuf + totallen && 
				(end_pos = memmem(ptr,totallen - (ptr - readbuf),"\r\n\r\n",4)) != NULL)
	{
		find_one = 0;
		for(i = 0 ; i < sizeof(cmd_dict)/sizeof(cmd_dict[0]) ; i ++)
		{
			if(memmem(ptr,totallen - (ptr-readbuf),cmd_dict[i].key_words,strlen(cmd_dict[i].key_words) ) != 0)
			{	
				find_one = 1;
				end_pos += 4;
				ret  = cmd_dict[i].handle(c,ptr,end_pos - ptr );
				retvalue |= ret;
				ptr = end_pos;

			}
		}

		//can not find any cmd key
		if(find_one == 0)
		{
			ptr = end_pos + 4;
		}
	}
	
	*parsed_len = ptr - readbuf ;

	//printf("parsed_len:%d\n",*parsed_len);
END:
	return retvalue;
}



