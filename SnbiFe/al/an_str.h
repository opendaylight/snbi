/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_STR_H__
#define __AN_STR_H__

#define AN_STR_MAX_LEN 128

uint8_t* an_strTrim(uint8_t *s);
uint16_t an_strlen(uint8_t *s);
uint16_t an_strnlen(uint8_t *s, uint16_t n);

boolean an_str_buffer_init(void);
boolean an_str_get_temp_buffer(an_buffer_t *buffer);
boolean an_str_alloc_and_copy_buffer(an_buffer_t *buffer, 
                    uint8_t **data, uint16_t *len, uint8_t *name);
boolean an_str_free_buffer(uint8_t *data);
int an_strcmp(const char *dest, const char *src);
char* an_strchr(const char *str, int n);
char* an_strstr(const char *searchee, const char *lookfor);
int an_strncmp(const char *cs, const char *ct, size_t n);
char* an_strtok(char *s, const char *ct);
int an_strncpy_s(char *dest, uint32_t dmax, const char *src, uint32_t slen);
int an_snprintf(char *str, unsigned int str_m, const char *fmt, ...);

#endif
