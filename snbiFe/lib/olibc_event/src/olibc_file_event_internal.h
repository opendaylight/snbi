#ifndef __OLIBC_FILE_EVENT_INTERNAL_H__
#define __OLIBC_FILE_EVENT_INTERNAL_H__

#include <olibc_common.h>
#include <olibc_file_event.h>

typedef struct olibc_file_event_t_ {
    int fd;
    struct event *event_handle;
    olibc_fd_event_func_t fd_event_cbk;
} olibc_file_event_t;

#endif
