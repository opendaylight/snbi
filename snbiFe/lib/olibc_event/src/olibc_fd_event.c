#include <string.h>
#include <olibc_log.h>
#include <event2/event.h>
#include "olibc_pthread_internal.h"
#include "olibc_fd_event_internal.h"

void 
olibc_fd_cbk (int fd, short type, void *args)
{
    olibc_fd_event_t fd_event;
    olibc_fd_event_listener_t *fd_listener = NULL;
    uint32_t event_flags = 0;

    if (!args) {
        return;
    }

    fd_listener = (olibc_fd_event_listener_t *)args;

    if (type & EV_READ) {
        event_flags |= OLIBC_FD_READ;
    }

    if (type & EV_WRITE) {
        event_flags |= OLIBC_FD_WRITE;
    }

    memset(&fd_event, 0, sizeof(olibc_fd_event_t));
    fd_event.fd = fd;
    fd_event.args = fd_listener->args;
    fd_event.event_type = event_flags;

    fd_listener->fd_listener_cbk(&fd_event);
}

olibc_retval_t
olibc_fd_event_get_fd (olibc_fd_event_hdl event_hdl, int *fd)
{
    if (!event_hdl || !fd) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    *fd = event_hdl->fd;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_fd_event_get_args (olibc_fd_event_hdl event_hdl, void **args)
{
    if (!event_hdl || !args) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    *args = event_hdl->args;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_fd_event_get_type (olibc_fd_event_hdl event_hdl, uint32_t *event_type)
{
    if (!event_hdl || !event_type) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    *event_type = event_hdl->event_type;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_fd_event_listener_create (olibc_fd_event_listener_hdl *fd_listener_hdl,
                              olibc_fd_event_listener_info_t *listener_info)
{
    olibc_retval_t retval;
    uint32_t event_flags = 0;
    struct event_base *evt_base = NULL;
    olibc_fd_event_listener_t *fd_listener = NULL;

    if (!fd_listener_hdl || !listener_info || !listener_info->fd_listener_cbk) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if ((retval = olibc_pthread_get_event_base(listener_info->pthread_hdl,
                    &evt_base)) != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    OLIBC_MALLOC_CHECK(fd_listener, sizeof(olibc_fd_event_listener_t),
                       __THIS_FUNCTION__, retval);

    fd_listener->fd = listener_info->fd;
    fd_listener->fd_listener_cbk = listener_info->fd_listener_cbk;

    evutil_make_socket_nonblocking(listener_info->fd);

    if (listener_info->fd_event_filter & OLIBC_FD_READ) {
        event_flags |= EV_READ;
    }

    if (listener_info->fd_event_filter & OLIBC_FD_WRITE) {
        event_flags |= EV_WRITE;
    }
    event_flags |= EV_PERSIST;

    fd_listener->event_handle = event_new(evt_base, listener_info->fd,
                                       event_flags, olibc_fd_cbk,
                                       fd_listener);
    if (!fd_listener->event_handle) {
        olibc_free((void **)&fd_listener);
        return OLIBC_RETVAL_FAILED;
    }

    event_add(fd_listener->event_handle, NULL);
    *fd_listener_hdl = fd_listener;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_fd_event_listener_destroy (olibc_fd_event_listener_hdl *fd_listener_hdl)
{
    olibc_fd_event_listener_t *fd_listener = NULL;

    if (!fd_listener_hdl) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    fd_listener = *fd_listener_hdl;

    if (event_del(fd_listener->event_handle)) {
        return OLIBC_RETVAL_FAILED;
    }

    event_free(fd_listener->event_handle);

    olibc_free((void **)fd_listener_hdl);

    return OLIBC_RETVAL_SUCCESS;
}
