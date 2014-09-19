/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_types.h"
#include "an_mem.h"
#include "an_str.h"


uint8_t buffer0[AN_STR_MAX_LEN] = {};
uint8_t buffer1[AN_STR_MAX_LEN] = {};
uint8_t buffer2[AN_STR_MAX_LEN] = {};
uint8_t buffer3[AN_STR_MAX_LEN] = {};
uint8_t buffer4[AN_STR_MAX_LEN] = {};
uint8_t buffer5[AN_STR_MAX_LEN] = {};
uint8_t buffer6[AN_STR_MAX_LEN] = {};
uint8_t buffer7[AN_STR_MAX_LEN] = {};
uint8_t buffer8[AN_STR_MAX_LEN] = {};
uint8_t buffer9[AN_STR_MAX_LEN] = {};

static uint8_t *buffer_p[10] = {};
static uint8_t *hex_array = "0123456789abcdef";

uint8_t*
an_strTrim (uint8_t *s)
{
    uint8_t *c = s + strlen(s);
    while (*(--c) == ' ' && c >= s)
        *c = '\0';
    return (s);

}

uint16_t
an_strlen (uint8_t *s)
{
    return (strnlen(s, AN_STR_MAX_LEN));
}

uint16_t
an_strnlen (uint8_t *s, uint16_t n)
{
    return (strnlen(s,n));
}

boolean
an_str_buffer_init (void)
{
    buffer_p[0] = buffer0;
    buffer_p[1] = buffer1;
    buffer_p[2] = buffer2;
    buffer_p[3] = buffer3;
    buffer_p[4] = buffer4;
    buffer_p[5] = buffer5;
    buffer_p[6] = buffer6;
    buffer_p[7] = buffer7;
    buffer_p[8] = buffer8;
    buffer_p[9] = buffer9;

    return (TRUE);
    
}

boolean
an_str_get_temp_buffer (an_buffer_t *buffer)
{
    static int8_t i = 0;

    buffer->data = buffer_p[i];
    buffer->len = 0;

    i = (i+1)%10;

    return (TRUE);

}

boolean
an_str_alloc_and_copy_buffer (an_buffer_t *buffer, uint8_t **data, uint16_t *len, uint8_t *name)
{
    if (!buffer || !data) {
        return (FALSE);
    }

    if (len) {
        *len = buffer->len;
    }
    *data = an_malloc_guard(buffer->len, name);
    if (!*data) {
        return (FALSE);
    }
    an_memcpy_guard(*data, buffer->data, buffer->len);

    return (TRUE);

}

boolean
an_str_free_buffer (uint8_t *data)
{
    if (data) {    
        an_free_guard(data);
    }    
    return (TRUE);
}

int
an_strcmp (const char *dest, const char *src)
{
    return (strcmp(dest,src));
}

char*
an_strchr (const char *str, int n)
{
   return (strchr(str, n));
}

char*
an_strstr (const char *searchee, const char *lookfor)
{
    return (strstr(searchee, lookfor));
}

int
an_strncmp (const char *cs, const char *ct, size_t n)
{
    return (strncmp(cs, ct, n));
}

char* an_strtok(char *s, const char *ct)
{
    return (strtok(s, ct));
}

int
an_strncpy_s (char *dest, uint32_t dmax, const char *src, uint32_t slen)
{
   strncpy(dest, src, dmax);     
   return (0);
}
/*
void 
an_strncpy (char *dest, uint32_t dmax, const char *src)
{
   strncpy(dest, src, dmax); 
   return (0);
}
*/

int an_snprintf (char *str, unsigned int str_m, const char *fmt, ...)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return 0;
}






