/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <an_types.h>
#include <an_mem.h>
#include <an_str.h>


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
//static uint8_t *hex_array = "0123456789abcdef";

uint8_t*
an_strTrim (uint8_t *s)
{
    if (!s) {
        return NULL;
    }

    uint8_t *c = s + strlen(s);
    while (*(--c) == ' ' && c >= s)
        *c = '\0';
    return (s);

}

uint16_t
an_strlen (uint8_t *s)
{
    if (!s) {
        return 0;
    }
    return (strnlen(s, AN_STR_MAX_LEN));
}

uint16_t
an_strnlen (uint8_t *s, uint16_t n)
{
    if (!s) {
        return 0;
    }
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

    if (!buffer) {
        return FALSE;
    }

    buffer->data = buffer_p[i];
    buffer->len = 0;

    i = (i+1)%10;

    return (TRUE);

}

boolean
an_str_alloc_and_copy_buffer (an_buffer_t *buffer, uint8_t **data, 
                              uint16_t *len, uint8_t *name)
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
    if (!data) {
        return FALSE;
    }

    an_free_guard(data);
    return (TRUE);
}

int
an_strcmp (const char *dest, const char *src)
{
    if (!dest || !src) {
        return 0;
    }
    return (strcmp(dest,src));
}

char*
an_strchr (const char *str, int n)
{
    if (!str) {
        return NULL;
    }
   return (strchr(str, n));
}

void
an_strstr (uint8_t *dest, uint16_t dLen, uint8_t *src,
                    uint16_t sLen, char **substr)
{
  //  return (strstr(searchee, lookfor));
}

int
an_strncmp (const char *cs, const char *ct, size_t n)
{
    if (!cs || !ct) {
        return 0;
    }
    return (strncmp(cs, ct, n));
}

char* an_strtok(char *s, const char *ct)
{
    if (!s || !ct) {
        return NULL;
    }
    return (strtok(s, ct));
}

an_errno
an_strncpy_s (char *dest, an_rsize dmax, const char *src, an_rsize slen)
{
    if (!dest || !src) {
        return 0;
    } 
    strncpy(dest, src, dmax);     
    return (0);
}

an_errno 
an_strncpy (char *dest, uint32_t dmax, const char *src)
{
    if (!dest || !src) {
        return 0;
    }
   strncpy(dest, src, dmax); 
   return EOK;
}

int an_snprintf (char *str, unsigned int str_m, const char *fmt, ...)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return 0;
}

an_rsize 
an_strnlen_s(const char *dest, an_rsize dmax) 
{
    if (!dest) {
        return 0;
    }
    return (strnlen(dest, dmax));
}

char* 
an_strstr_ns (const char *searchee, const char *lookfor) 
{
    if (!searchee || !lookfor) {
        return NULL;
    }
    return (strstr(searchee, lookfor));
}

an_errno 
an_strcmp_s (const char *dest, an_rsize dmax, 
             const char *src, int *indicator) 
{
    if (!dest || !src) {
        return EFAIL;
    }

    *indicator = -1;
    if (dest == src) {
        *indicator = 0;
        return EOK;
    }
    *indicator = strncmp (dest, src, dmax);
    return EOK;
}

char *an_strtok_r (char *s, const char *delim, 
                  char **lasts) 
{
    if (!s || !delim) {
        return NULL;
    }
    return (strtok_r(s, delim, lasts));
}

int
an_atoi (char *s)
{
    if (!s) {
        return 0;
    }
    return (atoi(s));
}

an_errno 
an_strcpy (uint8_t *dest, an_rsize dmax, uint8_t *src) 
{
    if (!dest || !src) {
        return EFAIL;
    }
    strncpy(dest, src, dmax);
    return EOK;
}

uint8_t
an_itoa_len (uint8_t num)
{
    uint8_t i = 0, len = 0, digit = 0, place = 0;

    for (i = 0; i < 3; i++)
    {
        place = 10^i;
        digit = (num%(place))/(place);
        if (digit) {
            len = i+1;
        }
    }
    return (len);
}

uint8_t * an_str_strtok (uint8_t *s, const uint8_t *delim) 
{
    if (!s) {
        return NULL;
    }
    return (strtok(s, delim));
}

boolean
an_str_convert_mac_addr_hex_to_str (an_mac_addr *mac_addr_str, an_mac_addr
                                    *mac_addr_hex, uint8_t length, 
                                     uint8_t separator)
{
    return TRUE;
}

uint8_t *
an_itoa (uint8_t num, uint8_t *str)
{
    uint8_t len = 0, place = 0, digit = 0, i = 0;

    if (!str) {
        return NULL;
    }

    len = an_itoa_len(num);
    for (i = 0; i < len; i++)
    {
        place = 10^i;
        digit = (num%(place))/(place);
        str[i] = digit + 48;
    }
    str[i] = '\n';
    return (str);
}

void
an_str_convert_mac_addr_str_to_hex (const an_mac_addr *macstr, an_mac_addr *buf)
{
    buf[0] = (an_str_atoh(macstr[0]) << 4) | an_str_atoh(macstr[1]);
    buf[1] = (an_str_atoh(macstr[2]) << 4) | an_str_atoh(macstr[3]);
    buf[2] = (an_str_atoh(macstr[5]) << 4) | an_str_atoh(macstr[6]);
    buf[3] = (an_str_atoh(macstr[7]) << 4) | an_str_atoh(macstr[8]);
    buf[4] = (an_str_atoh(macstr[10]) << 4) | an_str_atoh(macstr[11]);
    buf[5] = (an_str_atoh(macstr[12]) << 4) | an_str_atoh(macstr[13]);
}


void
an_str_get_device_suffix_in_hex (uint8_t *str, uint8_t *hexsuf)
{
    uint8_t str_temp[strlen(str)+1];
    uint8_t *token = NULL, *suf_temp = NULL;
    uint16_t temp,quotient;
    uint16_t suf_int, i=3;
    uint8_t hexadecimalNumber[4];

    an_memset(hexadecimalNumber, '0', 4);
    an_strncpy_s(str_temp,strlen(str)+1, str, strlen(str));

   /* get the device suffix */
    token = an_strchr(str_temp, AN_HOSTNAME_SUFFIX_DELIMITER);
    if(token != NULL) {
         suf_temp = token + 1;
    } else {
        return;
    }

    suf_int = atoi(suf_temp);
    quotient = suf_int;

    while (quotient!=0) {
        temp = quotient % 16;

        /*To convert integer into character*/
        if (temp < 10) {
           temp =temp + 48;
        } else {
           temp = temp + 55;
        }
        hexadecimalNumber[i--]= temp;
        quotient = quotient / 16;
    }

    hexsuf[0] = (an_str_atoh(hexadecimalNumber[0]) << 4) | 
                 an_str_atoh(hexadecimalNumber[1]);
    hexsuf[1] = (an_str_atoh(hexadecimalNumber[2]) << 4) | 
                 an_str_atoh(hexadecimalNumber[3]);
}

an_errno 
an_strcpy_s (char *dest, an_rsize dmax, const char *src) 
{
    if (!dest || !src) {
        return EFAIL;
    }

    strncpy(dest, src, dmax);
    return EOK;
}


int
an_str_atoh (uint8_t c)
{
    if (c >= '0' && c <= '9') {
        return(c - '0');
    }
    if (c >= 'A' && c <= 'F') {
        return(c - ('A' - 10));
    }
    if (c >= 'a' && c <= 'f') {
        return(c - ('a' - 10));
    }
    return(-1);
}
