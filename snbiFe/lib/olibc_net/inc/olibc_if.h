#ifndef __OLIBC_IF_H__
#define __OLIBC_IF_H__

#include <olibc_common.h>
#include <olibc_net.h>

#define OLIBC_MAX_IF_NAME_LEN 30
#define OLIBC_MAX_IF_HW_ADDR_LEN 6 // 48 bits of MAC address.

typedef enum olibc_hw_if_type_e_ {
    OLIBC_HW_IF_TYPE_ETHERNET = 1,
} olibc_hw_if_type_e;

typedef struct olibc_if_iterator_t_ *olibc_if_iterator_hdl;
typedef struct olibc_if_event_t_ *olibc_if_event_hdl;

typedef enum olibc_if_state_e_ {
    IF_UP,
    IF_DOWN
} olibc_if_state_e;

typedef struct olibc_if_info_t_ {
    char if_name[OLIBC_MAX_IF_NAME_LEN];
    uint32_t if_index;
    olibc_if_state_e if_state;
    boolean is_loopback;
    uint32_t hw_type;
    uint8_t hw_addr[OLIBC_MAX_IF_HW_ADDR_LEN];
    uint32_t hw_addr_len;
} olibc_if_info_t;

typedef struct olibc_if_event_info_t_ {
    uint32_t filter_flags;
} olibc_if_event_info_t;


typedef struct olibc_if_iterator_filer_t_ {
    uint32_t flags;
} olibc_if_iterator_filter_t;

olibc_retval_t
olibc_if_iterator_create(olibc_if_iterator_filter_t *if_iter_filter,
                         olibc_if_iterator_hdl *if_iter_hdl);

olibc_retval_t
olibc_if_iterator_get_next(olibc_if_iterator_hdl if_iter_hdl,
                           olibc_if_info_t *if_info_t);

olibc_retval_t
olibc_if_iterator_destroy(olibc_if_iterator_hdl *if_iter_hdl);

olibc_retval_t
olibc_if_event_create(olibc_if_event_info_t *if_event, 
                      olibc_if_event_hdl *event_hdl);

olibc_retval_t
olibc_if_event_destroy(olibc_if_event_hdl *event_hdl);

#endif
