/*************************************************************************
	> File Name: cmd_parse.c
	> Author: 
	> Mail: 
	> Created Time: Thu 01 Nov 2018 10:27:31 AM CST
 ************************************************************************/

#include <stdio.h>
#include <string.h>

#include "cmd_parse.h"


/*
 * The memmem() function finds the start of the first occurrence of the
 * substring 'needle' of length 'nlen' in the memory area 'haystack' of
 * length 'hlen'.
 *
 * The return value is a pointer to the beginning of the sub-string, or
 * NULL if the substring is not found.
 */
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

/*
int eventbase_copy_write_date(conn_t *c , void *buf, int len);
int eventbase_add_write_data(conn_t *c, const void *buf, int len); 

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


