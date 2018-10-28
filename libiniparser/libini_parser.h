#ifndef _lcfg_PARSER_H_
#define _lcfg_PARSER_H_

/*---------------------------------------------------------------------------
                                Includes
 ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The following #include is necessary on many Unixes but not Linux.
 * It is not needed for Windows platforms.
 * Uncomment it if needed.
 */
/* #include <unistd.h> */

#include "libini_dictionary.h"


#define MAX_FILENAME_PATH       (256)
#define KEY_NAME_SIZE           (64)
#define KEY_VALUE_SIZE          (512)
#define KEY_INT_NOTFOUND        (-101)
#define KEY_STRING_NOTFOUND     "UNDEF"

enum {
	TYPE_UCHAR = 0,
	TYPE_USHORT,
	TYPE_UINT,
	TYPE_INT,
	TYPE_STRING
};

#ifdef __cplusplus
extern "C" {
#endif

int lcfg_check_file_exist(const char *filepath);

int lcfg_file_copy(const char *psrcpath, const char *pdstpath);

/*--------------------------------------------------------------------------*/
const char * lcfg_key_getstring(const dictionary_t * d, const char * key, const char * def);

/*-------------------------------------------------------------------------*/
/**
  @brief    Get the string associated to a key, convert to an int
  @param    d Dictionary to search
  @param    key Key string to look for
  @param    notfound Value to return in case of error
  @return   integer

  This function queries a dictionary for a key. A key as read from an
  ini file is given as "section:key". If the key cannot be found,
  the notfound value is returned.

  Supported values for integers include the usual C notation
  so decimal, octal (starting with 0) and hexadecimal (starting with 0x)
  are supported. Examples:

  - "42"      ->  42
  - "042"     ->  34 (octal -> decimal)
  - "0x42"    ->  66 (hexa  -> decimal)

  Warning: the conversion may overflow in various ways. Conversion is
  totally outsourced to strtol(), see the associated man page for overflow
  handling.

  Credits: Thanks to A. Becker for suggesting strtol()
 */
/*--------------------------------------------------------------------------*/
//int lcfg_key_getint(const dictionary_t * d, const char * key, int notfound);
long long lcfg_key_getll(const dictionary_t * d, const char * key, int *notfound);



/*--------------------------------------------------------------------------*/
dictionary_t * lcfg_load_cfg(const char * ininame);

/*-------------------------------------------------------------------------*/
/**
  @brief    Free all memory associated to an ini dictionary
  @param    d Dictionary to free
  @return   void

  Free all memory associated to an ini dictionary.
  It is mandatory to call this function before the dictionary object
  gets out of the current context.
 */
/*--------------------------------------------------------------------------*/
void lcfg_free_cfg(dictionary_t * d);

#ifdef __cplusplus
}
#endif

#endif
