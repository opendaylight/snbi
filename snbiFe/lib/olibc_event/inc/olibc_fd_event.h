#ifndef __OLIBC_FD_EVENT_H__
#define __OLIBC_FD_EVENT_H__

#include <olibc_common.h>
#include <olibc_pthread.h>

typedef struct olibc_fd_event_t_* olibc_fd_event_hdl;

#define OLIBC_FD_READ 0x01
#define OLIBC_FD_WRITE 0x02

typedef boolean (*olibc_fd_event_func_t) (int fd, uint32_t ev_type);

typedef struct olibc_fd_event_info_t_ {
    int fd;
    uint32_t fd_event_filter;
    olibc_pthread_hdl pthread_hdl;
    olibc_fd_event_func_t fd_event_cbk;
} olibc_fd_event_info_t;

olibc_retval_t
olibc_fd_event_create(olibc_fd_event_hdl *fd_event_hdl,
                        olibc_fd_event_info_t *fd_info);

olibc_retval_t
olibc_fd_event_destroy(olibc_fd_event_hdl *fd_event_hdl);

#endif
