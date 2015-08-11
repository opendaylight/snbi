#ifndef __OLIBC_FILE_EVENT_INTERNAL_H__
#define __OLIBC_FILE_EVENT_INTERNAL_H__

#include <olibc_common.h>
#include <olibc_fd_event.h>

typedef struct olibc_fd_event_listener_t_ {
    int fd;
    void *args;
    struct event *event_handle;
    olibc_fd_listener_func_t fd_listener_cbk;
} olibc_fd_event_listener_t;

typedef struct olibc_fd_event_t_ {
    int fd;
    void *args;
    uint32_t event_type;
} olibc_fd_event_t;

#endif
