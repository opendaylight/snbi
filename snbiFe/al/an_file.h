/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_FILE_H__
#define __AN_FILE_H__

#include "an_str.h"

#define AN_FILE_MAX_READ_SIZE AN_STR_MAX_LEN

typedef enum an_file_api_ret_enum_ {
    AN_FILE_API_SUCCESS,
    
    AN_FILE_INPUT_PARAM_INVALID,
    AN_FILE_OPEN_FAIL,
    AN_FILE_SIZE_INVALID,
    AN_FILE_INVALID_DESCR,
    AN_FILE_MEM_ALLOC_FAIL,
    AN_FILE_SIZE_NOT_EQUAL,
    AN_FILE_WRITE_FAIL,
    AN_FILE_READ_MAX,
    AN_FILE_READ_FAIL,
    AN_FILE_NAME_NOT_EXIST,
    AN_FILE_ENUM_MAX,
    AN_FILE_READ_CHAR_SUCCESS,
    AN_FILE_READ_CHAR_FAIL,
    AN_FILE_READ_EOF,

} an_file_api_ret_enum;

extern const uint8_t *an_file_enum_get_string (an_file_api_ret_enum enum_type);
extern const an_file_descr_t AN_FILE_DESCR_INVALID;

boolean an_file_descr_is_valid(an_file_descr_t fd);

an_file_api_ret_enum 
an_file_open_read_close(uint8_t *filename, uint8_t **data, uint32_t *data_len);

an_file_api_ret_enum 
an_file_open_write_close(uint8_t *filename, uint8_t *data, uint32_t data_len);

an_file_api_ret_enum 
an_file_exist(uint8_t *filename);

an_file_descr_t an_file_open(uint8_t *filename, an_file_open_flags_e flags);
boolean an_file_close(an_file_descr_t fd);
boolean an_file_delete(uint8_t *filename);

an_file_api_ret_enum
an_file_seek(an_file_descr_t fd, uint32_t offset, an_file_seek_ref_e seek_ref);

an_file_api_ret_enum
an_file_read_next_char(an_file_descr_t fd, int8_t *ch);

boolean
an_file_is_next_word_udi(an_file_descr_t fd);

an_file_api_ret_enum
an_file_read_next_byte(an_file_descr_t fd, uint8_t *ch);

an_file_api_ret_enum
an_file_read_next_word(an_file_descr_t fd, an_buffer_t *word, uint32_t max_len);

an_file_api_ret_enum
an_file_read_next_pub_key(an_file_descr_t fd, an_buffer_t *word, 
                          uint16_t to_read_len);

an_file_api_ret_enum 
an_file_read_next_udi(an_file_descr_t fd, an_udi_t *udi, uint32_t max_len);

an_file_api_ret_enum
an_file_read_next_line(an_file_descr_t fd, an_buffer_t *line, uint32_t max_len);

an_file_api_ret_enum
an_file_write_char(an_file_descr_t fd, int8_t *ch);

an_file_api_ret_enum
an_file_write_byte(an_file_descr_t fd, uint8_t *ch);

an_file_api_ret_enum
an_file_write_pub_key(an_file_descr_t fd, an_key_t *key);

an_file_api_ret_enum
an_file_write_word(an_file_descr_t fd, an_buffer_t *word);

an_file_api_ret_enum
an_file_write_line(an_file_descr_t fd, an_buffer_t *line);

an_file_api_ret_enum 
an_file_write_line_terminator(an_file_descr_t fd);
boolean an_file_copy_to_standby(uint8_t *src_file);
void an_file_delete_from_standby(uint8_t *src_file);
void an_file_copy_to_stby_later(uint8_t *filename);
void an_write_device_from_db_to_local_file(void *device, 
                                                uint8_t file_identifier);
#endif
