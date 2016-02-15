#ifndef __OLIBC_ADDR_EVENT_H__
#define __OLIBC_ADDR_EVENT_H__

#include <olibc_common.h>
#include <olibc_net.h>
#include <olibc_if.h>
#include <olibc_pthread.h>
#include <olibc_fd_event.h>
#include <olibc_addr.h>

typedef struct
olibc_addr_event_listener_t_* olibc_addr_event_listener_hdl;

typedef struct olibc_addr_event_t_* olibc_addr_event_hdl;
typedef boolean (*olibc_addr_event_listener_func_t)
        (olibc_addr_event_hdl addr_event);

typedef struct olibc_addr_event_listener_info_t_ {
    void *args;
    uint32_t flags;
    olibc_addr_event_listener_func_t addr_event_listener_cbk;
    olibc_pthread_hdl pthread_hdl;
} olibc_addr_event_listener_info_t;

olibc_retval_t
olibc_addr_event_listener_create(
        olibc_addr_event_listener_info_t *addr_event_listener_info,
        olibc_addr_event_listener_hdl *addr_event_listener_hdl);

olibc_retval_t
olibc_addr_event_listener_destroy(
        olibc_addr_event_listener_hdl *addr_event_listener_hdl);

olibc_retval_t
olibc_addr_event_get_iterator(olibc_addr_event_hdl addr_event_hdl,
                olibc_addr_iterator_hdl *addr_iterator_hdl);

olibc_retval_t
olibc_addr_event_get_args(olibc_addr_event_hdl addr_event_hdl, void** args);

#endif
