#ifndef __OLIBC_ADDR_H__
#define __OLIBC_ADDR_H__

#include <olibc_common.h>
#include <olibc_net.h>
#include <netinet/in.h>

typedef struct olibc_addr_iterator_t_ *olibc_addr_iterator_hdl;

typedef enum olibc_addr_scope_e_ {
    OLIBC_ADDR_SCOPE_UNIVERSE,
    OLIBC_ADDR_SCOPE_SITE,
    OLIBC_ADDR_SCOPE_LINK,
    OLIBC_ADDR_SCOPE_HOST,
    OLIBC_ADDR_SCOPE_NOWHERE
} olibc_addr_scope_e;

typedef struct olibc_addr_info_t {
    uint8_t addr_family;
    union {
        struct in6_addr addrv6;
        struct in_addr addrv4;
    };
    uint8_t prefixlen;
    uint16_t scope;
} olibc_addr_info_t;

typedef struct olibc_addr_iterator_filter_t_ {
    uint32_t flags;
} olibc_addr_iterator_filter_t;

extern olibc_retval_t
olibc_addr_iterator_create(olibc_addr_iterator_filter_t *filter_info,
                           olibc_addr_iterator_hdl *iter_hdl);

extern olibc_retval_t  
olibc_addr_iterator_get_next(olibc_addr_iterator_hdl iter_hdl, 
                             olibc_addr_info_t *addr, 
                             uint32_t *if_index);

extern olibc_retval_t
olibc_addr_iteratfor_destroy(olibc_addr_iterator_hdl *iter_hdl);
                             
#endif
