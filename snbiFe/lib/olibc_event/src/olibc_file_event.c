#include <olibc_log.h>
#include <event2/event.h>
#include "olibc_pthread_internal.h"
#include "olibc_file_event_internal.h"

void 
olibc_file_cbk (int fd, short type, void *args)
{
    olibc_file_event_t *file_event = NULL;
    uint32_t event_flags = 0;

    if (!args) {
        return;
    }

    file_event = (olibc_file_event_t *)args;

    if (type & EV_READ) {
        event_flags |= OLIBC_FD_READ;
    }

    if (type & EV_WRITE) {
        event_flags |= OLIBC_FD_WRITE;
    }

    file_event->fd_event_cbk(fd, event_flags);
}
    

olibc_retval_t
olibc_file_event_create (olibc_file_event_hdl *file_event_hdl,
                         olibc_file_event_info_t *file_info)
{
    olibc_retval_t retval;
    uint32_t event_flags = 0;
    struct event_base *evt_base = NULL;
    olibc_file_event_t *file_event = NULL;

    if (!file_event_hdl || !file_info) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if ((retval = olibc_pthread_get_event_base(file_info->pthread_hdl,
                    &evt_base)) != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    OLIBC_MALLOC_CHECK(file_event, sizeof(olibc_file_event_t),
                       __THIS_FUNCTION__, retval);

    file_event->fd = file_info->fd;
    file_event->fd_event_cbk = file_info->fd_event_cbk;

    if (file_info->fd_event_filter & OLIBC_FD_READ) {
        event_flags |= EV_READ;
    }

    if (file_info->fd_event_filter & OLIBC_FD_WRITE) {
        event_flags |= EV_WRITE;
    }
    event_flags |= EV_PERSIST;

    file_event->event_handle = event_new(evt_base, file_info->fd,
                                         event_flags, olibc_file_cbk,
                                         file_event);
    if (!file_event->event_handle) {
        olibc_free((void **)&file_event);
        return OLIBC_RETVAL_FAILED;
    }

    event_add(file_event->event_handle, NULL);
    *file_event_hdl = file_event;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_file_event_destroy (olibc_file_event_hdl *file_event_hdl)
{
    olibc_file_event_t *file_event = NULL;

    if (!file_event_hdl) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    file_event = *file_event_hdl;

    if (event_del(file_event->event_handle)) {
        return OLIBC_RETVAL_FAILED;
    }

    event_free(file_event->event_handle);

    olibc_free((void **)file_event_hdl);

    return OLIBC_RETVAL_SUCCESS;
}
