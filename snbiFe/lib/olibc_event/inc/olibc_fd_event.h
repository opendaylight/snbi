#ifndef __OLIBC_FD_EVENT_H__
#define __OLIBC_FD_EVENT_H__

#include <olibc_common.h>
#include <olibc_pthread.h>

typedef struct olibc_fd_event_listener_t_* olibc_fd_event_listener_hdl;
typedef struct olibc_fd_event_t_* olibc_fd_event_hdl;

#define OLIBC_FD_READ 0x01
#define OLIBC_FD_WRITE 0x02

typedef boolean (*olibc_fd_listener_func_t) (olibc_fd_event_hdl fd_event);

typedef struct olibc_fd_event_listener_info_t_ {
    int fd;
    void *args;
    uint32_t fd_event_filter;
    olibc_pthread_hdl pthread_hdl;
    olibc_fd_listener_func_t fd_listener_cbk;
} olibc_fd_event_listener_info_t;

olibc_retval_t
olibc_fd_event_listener_create(olibc_fd_event_listener_hdl *listener_hdl,
                               olibc_fd_event_listener_info_t *listener_info);

olibc_retval_t
olibc_fd_event_listener_destroy(olibc_fd_event_listener_hdl *listener_hdl);

olibc_retval_t
olibc_fd_event_get_fd(olibc_fd_event_hdl event_hdl, int *fd);

olibc_retval_t
olibc_fd_event_get_args(olibc_fd_event_hdl event_hdl, void **args);

olibc_retval_t
olibc_fd_event_get_type(olibc_fd_event_hdl event_hdl, uint32_t *event_type);

#endif
