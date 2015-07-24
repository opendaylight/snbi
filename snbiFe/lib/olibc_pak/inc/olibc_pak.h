#ifndef __OLIBC_PAK_H__
#define __OLIBC_PAK_H__

#include <olibc_common.h>
#include <olibc_net.h>

typedef struct olibc_pak_t_* olibc_pak_hdl;

typedef struct olibc_pak_info_t_ {
    uint32_t addr_family;
    uint32_t pak_length;
} olibc_pak_info_t;

olibc_retval_t
olibc_pak_create(olibc_pak_hdl *pak_hdl, olibc_pak_info_t *pak_info);

olibc_retval_t
olibc_pak_destroy(olibc_pak_hdl *pak_hdl);

olibc_retval_t
olibc_pak_recv(olibc_pak_hdl pak_hdl, int fd, uint32_t offset_bytes);

olibc_retval_t
olibc_pak_send(olibc_pak_hdl pak_hdl, int fd, uint32_t offset_bytes);

olibc_retval_t
olibc_pak_get_data_buffer(olibc_pak_hdl pak_hdl,
                          uint8_t **data_buff, 
                          uint32_t *data_len);

olibc_retval_t
olibc_pak_get_in_if_index(olibc_pak_hdl pak_hdl,
                          uint32_t *if_index);

olibc_retval_t
olibc_pak_get_out_if_index(olibc_pak_hdl pak_hdl,
                          uint32_t *if_index);

olibc_retval_t
olibc_pak_set_out_if_index(olibc_pak_hdl pak_hdl,
                           uint32_t if_index);

olibc_retval_t
olibc_pak_set_in_if_index(olibc_pak_hdl pak_hdl,
                          uint32_t if_index);

olibc_retval_t
olibc_pak_get_length(olibc_pak_hdl pak_hdl, uint32_t *data_length);

olibc_retval_t
olibc_pak_set_length(olibc_pak_hdl pak_hdl, uint32_t data_length);
 
olibc_retval_t
olibc_pak_get_src_addr(olibc_pak_hdl pak_hdl,
                       struct sockaddr_storage *sock_addr);

olibc_retval_t
olibc_pak_get_dst_addr(olibc_pak_hdl pak_hdl,
                       struct sockaddr_storage *sock_addr);

olibc_retval_t
olibc_pak_set_src_addr(olibc_pak_hdl pak_hdl,
                       struct sockaddr *sock_addr);

olibc_retval_t
olibc_pak_set_dst_addr(olibc_pak_hdl pak_hdl,
                       struct sockaddr *sock_addr);
#endif
