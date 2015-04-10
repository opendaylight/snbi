/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_logger.h>
#include <an_addr.h>
#include <an_mem.h>
#include <an_str.h>
#include <an_sudi.h>
#include <an_file.h>
#include <an_file_linux.h>
#include <an_acp.h>


const an_file_descr_t AN_FILE_DESCR_INVALID = -1;

an_file_api_ret_enum
an_file_open_read_close (uint8_t *filename, uint8_t **p_data, uint32_t *p_data_len)
{
    int fd = AN_FILE_DESCR_INVALID;
    int file_size = 0;
    uint32_t data_len = 0;
    uint8_t *data = NULL;

    if (!filename || !p_data || !p_data_len) {
        return (AN_FILE_INPUT_PARAM_INVALID);
    }

    *p_data = NULL;
    *p_data_len = 0;

    fd = open(filename, 0x0001, 0);
    if (fd < 0) {
        return (AN_FILE_OPEN_FAIL);
    }

    file_size = ifs_fd_get_size(fd);
    if (file_size < 0) {
        close(fd);
        return (AN_FILE_SIZE_INVALID);
    }
    if (!an_file_descr_is_valid(fd)) {
        close(fd);
        return (AN_FILE_INVALID_DESCR);
    }

    data = (uint8_t *)an_malloc_guard(file_size, "AN File Read");
    if (!data) {
        close(fd);
        return (AN_FILE_MEM_ALLOC_FAIL);
    }
    data_len = read(fd, data, file_size);
    if (data_len != file_size) {
        close(fd);
        an_free_guard(data);
        return (AN_FILE_SIZE_NOT_EQUAL);
    }

    close(fd);

    *p_data = data;
    *p_data_len = data_len;
    return (AN_FILE_API_SUCCESS);

}

an_file_api_ret_enum
an_file_open_write_close (uint8_t *filename, uint8_t *data, uint32_t data_len)
{
    int fd = AN_FILE_DESCR_INVALID;

    if (!filename || !data || !data_len) {
        return (AN_FILE_INPUT_PARAM_INVALID);
    }

    fd = open(filename, 0x0001, 0);
    if (!an_file_descr_is_valid(fd)) {
        return (AN_FILE_OPEN_FAIL);
    }

    if (ifs_write_until(fd, data, data_len) < 0) {
        close(fd);
        return (AN_FILE_WRITE_FAIL);
    }

    close(fd);
    return (AN_FILE_API_SUCCESS);
}

an_file_descr_t
an_file_open (uint8_t *filename, an_file_open_flags_e flags)
{
    int fd = AN_FILE_DESCR_INVALID;

    if (!filename) {
        return (AN_FILE_DESCR_INVALID);
    }

    fd = open(filename, flags|AN_FOF_CREATE , S_IRWXU | S_IRWXG | S_IRWXO);
    if (!an_file_descr_is_valid(fd)) {
        return (AN_FILE_DESCR_INVALID);
    }

    return (fd);
}

boolean
an_file_close (an_file_descr_t fd)
{
    close(fd);
    return (TRUE);
}

boolean
an_file_delete (uint8_t *filename)
{
    remove(filename);
    return (TRUE);
}

an_file_api_ret_enum
an_file_seek (an_file_descr_t fd, uint32_t offset, an_file_seek_ref_e seek_ref)
{
    if (!an_file_descr_is_valid(fd)) {
        return (AN_FILE_INVALID_DESCR);
    }

    lseek(fd, offset, seek_ref);
    return (AN_FILE_API_SUCCESS);

}

an_file_api_ret_enum
an_file_read_next_char (an_file_descr_t fd, int8_t *ch)
{
    int bytes_to_read;

    if (!an_file_descr_is_valid(fd)) {
        return (AN_FILE_INVALID_DESCR);
    }

    bytes_to_read = read(fd, ch, sizeof(int8_t));
    if (bytes_to_read == 0) {   // EOF
        *ch = EOF;
        return (AN_FILE_READ_CHAR_SUCCESS);
    }
    if (bytes_to_read < 0) {
        return (AN_FILE_READ_CHAR_FAIL);
    }

    return (AN_FILE_API_SUCCESS);

}

an_file_api_ret_enum
an_file_write_char (an_file_descr_t fd, int8_t *ch)
{
    if (!an_file_descr_is_valid(fd)) {
        return (AN_FILE_INVALID_DESCR);
    }

    write(fd, ch, 1);

    return (AN_FILE_API_SUCCESS);

}

/* word->data should be a NULL terminated string */
an_file_api_ret_enum
an_file_write_word (an_file_descr_t fd, an_buffer_t *word)
{
    if (!an_file_descr_is_valid(fd)) {
        return (AN_FILE_INVALID_DESCR);
    }

    write(fd, word->data, word->len - 1);
    if (word->data[word->len - 2] != ' ') {
        write(fd, " ", 1);
    }

    return (AN_FILE_API_SUCCESS);

}

/* line->data should be a NULL terminated string */
an_file_api_ret_enum
an_file_write_line (an_file_descr_t fd, an_buffer_t *line)
{
    if (!an_file_descr_is_valid(fd)) {
        return (AN_FILE_INVALID_DESCR);
    }

    write(fd, line->data, line->len - 1);
    if (line->data[line->len - 2] != '\n') {
        write(fd, "\n", 1);
    }

    return (AN_FILE_API_SUCCESS);
}

an_file_api_ret_enum
an_file_write_fs (an_file_descr_t fd, const char *fmt, va_list args)
{
    if (!an_file_descr_is_valid(fd)) {
        return (AN_FILE_INVALID_DESCR);
    }

    dprintf(fd, fmt, args);

    return (AN_FILE_API_SUCCESS);
}


an_file_api_ret_enum
an_file_exist (uint8_t *filename)
{
    struct stat sbuf;
    int rc;

    rc = stat(filename, &sbuf);
    if (rc < 0) {
        /*
         * File does not exist. 
         */
        return (AN_FILE_NAME_NOT_EXIST);
    }

    if (sbuf.st_size == 0) {
        /*
         * File is empty.
         */
        return (AN_FILE_READ_FAIL);
    }

    if (!(sbuf.st_mode & S_IRUSR)) {
        /*
         * File is not readable.
         */
        return (AN_FILE_READ_FAIL);
    }

    return (AN_FILE_API_SUCCESS);

}

void 
an_file_copy_to_stby_later (uint8_t *filename) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void 
an_write_device_from_db_to_local_file (void *device, uint8_t file_identifier) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

boolean 
an_file_copy_to_standby(uint8_t *src_file) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return FALSE;
}

uint32_t 
ifs_fd_get_size (int fd) {

    struct stat stat_block;
    int rc;

     /*
      * Attempt to fill a stat block for this file descriptor
      */
    rc = fstat(fd, &stat_block);
    if (rc < 0)
        return(rc);
    else
        return((int)stat_block.st_size);

    return(-1);

}

uint32_t ifs_write_until (int fd, void *vbuffer, uint32_t nbytes)
{
    int rc;
    int written = 0;
    char *buffer = vbuffer;

    while (nbytes) {
        rc = write(fd, buffer, nbytes);
        if (rc <= 0) {
            written = -1;
            break;
        }

        nbytes -= rc;
        buffer += rc;
        written += rc;
    }

    return (written);
}

void
an_file_delete_from_standby (uint8_t *src_file)
{
}

