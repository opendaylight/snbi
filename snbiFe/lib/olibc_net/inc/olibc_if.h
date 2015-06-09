#ifndef __OLIBC_IF_H__
#define __OLIBC_IF_H__

#include <olibc_common.h>

#define MAX_IF_NAME_LEN 30

typedef struct olibc_if_iterator_t_ *olibc_if_iterator_hdl;

typedef enum olibc_if_state_e_ {
    IF_UP,
    IF_DOWN
} olibc_if_state_e;

typedef struct olibc_if_info_t_ {
    char if_name[MAX_IF_NAME_LEN];
    uint32_t if_index;
    olibc_if_state_e if_state;
    boolean is_loopback;
} olibc_if_info_t;

typedef struct olibc_if_event_info_t_ {
    uint32_t filter_flags;


#define IF_ITER_FILTER_FLAG_IPV4 0x01
#define IF_ITER_FILTER_FLAG_IPV6 0x02

typedef struct olibc_if_iterator_filer_t_ {
    uint32_t filter_flags;
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
olibc_if_event_create(

#endif
