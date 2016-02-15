#ifndef __OLIBC_ADDR_EVENT_INTERNAL_H__
#define __OLIBC_ADDR_EVENT_INTERNAL_H__

#include <olibc_common.h>
#include <olibc_fd_event.h>
#include <olibc_addr.h>
#include <olibc_addr_event.h>

typedef struct olibc_addr_event_listener_t_ {
    void *args;
    uint32_t flags;
    olibc_addr_event_listener_func_t addr_event_listener_cbk;
    olibc_fd_event_listener_hdl fd_event_listener_hdl;
    olibc_nl_sock_t addr_event_nl_sock_addr;
} olibc_addr_event_listener_t;

typedef struct olibc_addr_event_t_ {
    void *args;
    struct olibc_addr_iterator_t_ *addr_iterator;
} olibc_addr_event_t;

#endif
