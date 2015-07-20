#include <olibc_log.h>
#include <event2/event.h>
#include "olibc_pthread_internal.h"
#include "olibc_fd_event_internal.h"

void 
olibc_fd_cbk (int fd, short type, void *args)
{
    olibc_fd_event_t *fd_event = NULL;
    uint32_t event_flags = 0;

    if (!args) {
        return;
    }

    fd_event = (olibc_fd_event_t *)args;

    if (type & EV_READ) {
        event_flags |= OLIBC_FD_READ;
    }

    if (type & EV_WRITE) {
        event_flags |= OLIBC_FD_WRITE;
    }

    fd_event->fd_event_cbk(fd, event_flags);
}
    

olibc_retval_t
olibc_fd_event_create (olibc_fd_event_hdl *fd_event_hdl,
                         olibc_fd_event_info_t *fd_info)
{
    olibc_retval_t retval;
    uint32_t event_flags = 0;
    struct event_base *evt_base = NULL;
    olibc_fd_event_t *fd_event = NULL;

    if (!fd_event_hdl || !fd_info) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if ((retval = olibc_pthread_get_event_base(fd_info->pthread_hdl,
                    &evt_base)) != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    OLIBC_MALLOC_CHECK(fd_event, sizeof(olibc_fd_event_t),
                       __THIS_FUNCTION__, retval);

    fd_event->fd = fd_info->fd;
    fd_event->fd_event_cbk = fd_info->fd_event_cbk;

    evutil_make_socket_nonblocking(fd_info->fd);

    if (fd_info->fd_event_filter & OLIBC_FD_READ) {
        event_flags |= EV_READ;
    }

    if (fd_info->fd_event_filter & OLIBC_FD_WRITE) {
        event_flags |= EV_WRITE;
    }
    event_flags |= EV_PERSIST;

    fd_event->event_handle = event_new(evt_base, fd_info->fd,
                                       event_flags, olibc_fd_cbk,
                                       fd_event);
    if (!fd_event->event_handle) {
        olibc_free((void **)&fd_event);
        return OLIBC_RETVAL_FAILED;
    }

    event_add(fd_event->event_handle, NULL);
    *fd_event_hdl = fd_event;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_fd_event_destroy (olibc_fd_event_hdl *fd_event_hdl)
{
    olibc_fd_event_t *fd_event = NULL;

    if (!fd_event_hdl) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    fd_event = *fd_event_hdl;

    if (event_del(fd_event->event_handle)) {
        return OLIBC_RETVAL_FAILED;
    }

    event_free(fd_event->event_handle);

    olibc_free((void **)fd_event_hdl);

    return OLIBC_RETVAL_SUCCESS;
}
