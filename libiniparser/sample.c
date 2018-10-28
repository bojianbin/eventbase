#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "libini_parser.h"

enum
{
    /* section cmds */
    CMD_GET,
    CMD_SET,
    CMD_RELOAD,
    CMD_HELP
};


static void cfg_usage(void)
{
	fprintf(stderr,
		"Usage: cfg  <command>  [<arguments>]\n\n"
		"Commands:\n"
		"\tget        <config> <section> <key> \n"
		"\n");
}


int main(int argc, char *argv[])
{
	int ret = -1;	
	int cmd;
	char tmp_str[KEY_VALUE_SIZE];
	const char *sval;
	dictionary_t *dic;

	if (argc <= 1){
		cfg_usage();
		exit(0);
	}
	
	
	if (!strcasecmp(argv[1], "get"))
		cmd = CMD_GET;
	else
		cmd = CMD_HELP;


	switch (cmd) {

	case CMD_GET:
		if (argc < 5)
			return ret;
		
		dic = lcfg_load_cfg(argv[2]);
        	if (!dic) {
			fprintf(stderr, "lcfg_load_cfg %s failed\n", argv[2]);
			return -1;
        	}
		memset(tmp_str, 0, KEY_VALUE_SIZE);
		sprintf(tmp_str, "%s:%s", argv[3], argv[4]);
		sval = lcfg_key_getstring(dic, tmp_str, KEY_STRING_NOTFOUND);
		if (strcmp(sval, KEY_STRING_NOTFOUND)) {
			printf("%s\n", sval);
		}
		lcfg_free_cfg(dic);
		break;
	case CMD_HELP:
		cfg_usage();
		ret = 0;
		break;	

	}

	return ret;	
}
