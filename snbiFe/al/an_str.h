/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_STR_H__
#define __AN_STR_H__
#include "an_types.h"

#define AN_STR_MAX_LEN 128
#define AN_UDI_MAX_LEN 128
#define AN_PID_PREFIX_LEN 4
#define AN_HOSTNAME_SUFFIX_DELIMITER '-'

uint8_t* an_strTrim(uint8_t *s);
uint16_t an_strlen(uint8_t *s);
uint16_t an_strnlen(uint8_t *s, uint16_t n);
an_errno an_strcpy(uint8_t *dest, an_rsize dmax, uint8_t *src);
an_errno an_strcpy_s(char *dest, an_rsize dmax, const char *src);
an_errno an_strncpy_s(char *dest, an_rsize dmax, const char *src, an_rsize slen);
an_rsize an_strnlen_s(const char *dest, an_rsize dmax);
an_errno an_strcmp_s(const char *dest, an_rsize dmax, const char *src, int *indicator);
int an_atoi(char *s);

boolean an_str_buffer_init(void);
boolean an_str_get_temp_buffer(an_buffer_t *buffer);
boolean an_str_alloc_and_copy_buffer(an_buffer_t *buffer, 
                    uint8_t **data, uint16_t *len, uint8_t *name);
boolean an_str_free_buffer(uint8_t *data);
char* an_strstr_ns(const char *searchee, const char *lookfor);
int an_strncmp(const char *cs, const char *ct, size_t n);
char* an_strtok(char *s, const char *ct);
//int an_strncpy_s(char *dest, uint32_t dmax, const char *src, uint32_t slen);
int an_snprintf(char *str, unsigned int str_m, const char *fmt, ...);
int an_sprintf(char *str, const char *fmt, ...);

int an_strcmp (const char *dest, const char *src);
uint8_t * an_str_strtok(uint8_t *s, const uint8_t *delim);
boolean an_str_convert_mac_addr_hex_to_str(uint8_t *mac_addr_str, an_mac_addr *mac_addr_hex, 
                                            uint8_t length, uint8_t separator);
int an_str_atoh(uint8_t c);
void an_str_get_device_suffix_in_hex(uint8_t *str, uint8_t *hexsuf);
void an_str_convert_mac_addr_str_to_hex(const uint8_t *macstr, an_mac_addr *buf);
void an_strstr(uint8_t *dest, uint16_t dLen, uint8_t *src,
            uint16_t sLen, char **substr);
uint8_t *an_itoa(uint8_t num, uint8_t *str);
char *an_strtok_r(char *s, const char *delim, char **lasts);

#endif
