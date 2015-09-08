#ifndef __OLIBC_IF_EVENT_INTERNAL_H__
#define __OLIBC_IF_EVENT_INTERNAL_H__

#include <olibc_common.h>
#include <olibc_if_event.h>
#include <olibc_if.h>
#include <olibc_fd_event.h>

typedef struct olibc_if_event_listener_t_ {
    void *args;
    olibc_if_event_listener_func_t if_event_listener_cbk;
    olibc_fd_event_listener_hdl	fd_event_listener_hdl;
    olibc_nl_sock_t if_event_nl_sock_addr;
} olibc_if_event_listener_t;

typedef struct olibc_if_event_t_ {
    void *args;
    struct olibc_if_iterator_t_ *if_iterator;
} olibc_if_event_t;

#endif
