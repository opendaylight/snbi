#include <olibc_common.h>
#include "olibc_rt_netlink.h"
#include "olibc_addr_event_internal.h"
#include "olibc_netlink.h"
#include "olibc_addr_rt_netlink.h"
#include <event2/event.h>
#include <string.h>
#include <olibc_log.h>

boolean
olibc_addr_event_cbk (olibc_fd_event_hdl fd_event_hdl)
{
    olibc_retval_t retval;
    struct olibc_addr_iterator_t_ *addr_iterator;
    uint32_t ev_type = 0;
    olibc_addr_event_t addr_event;
    olibc_addr_event_listener_t *addr_event_listener = NULL;

    if (!fd_event_hdl) {
        return FALSE;
    }

    retval = olibc_fd_event_get_type(fd_event_hdl, &ev_type);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }

    if (!(ev_type & OLIBC_FD_READ)) {
        return FALSE;
    }

    retval = olibc_fd_event_get_args(fd_event_hdl,
            (void **) &addr_event_listener);
    olibc_addr_event_listener_func_t addr_event_listener_cbk =
        addr_event_listener->addr_event_listener_cbk;


    if (addr_event_listener_cbk) {
        OLIBC_MALLOC_CHECK(addr_iterator, sizeof(struct olibc_addr_iterator_t_),
                       __THIS_FUNCTION__, retval);
        memset(&addr_event, 0, sizeof(olibc_addr_event_t));
        addr_iterator->nl_sock = addr_event_listener->addr_event_nl_sock_addr;
        addr_event.addr_iterator = addr_iterator;
        addr_event.args = addr_event_listener->args;

        addr_iterator->oper_flags |= (OLIBC_ADDR_OPER_FLAG_IPV4_REQ_SENT |
                                      OLIBC_ADDR_OPER_FLAG_IPV6_REQ_SENT);

        if (!(addr_event_listener->flags & OLIBC_FLAG_IPV4)) {
            addr_iterator->oper_flags |= (OLIBC_ADDR_OPER_FLAG_IPV4_ITER_DONE);
        } else {
            addr_iterator->oper_flags |= (OLIBC_ADDR_OPER_FLAG_IPV4_ITERATION);
        }

        if (!(addr_event_listener->flags & OLIBC_FLAG_IPV6)) {
            addr_iterator->oper_flags |= (OLIBC_ADDR_OPER_FLAG_IPV6_ITER_DONE);
        } else {
            addr_iterator->oper_flags |= (OLIBC_ADDR_OPER_FLAG_IPV6_ITERATION);
        }

        addr_event_listener_cbk(&addr_event);
        olibc_free((void**) &addr_iterator);
    }
    return TRUE;
}


olibc_retval_t
olibc_addr_event_listener_create (
        olibc_addr_event_listener_info_t *addr_event_listener_info,
        olibc_addr_event_listener_hdl *addr_event_listener_hdl)
{
    int groups = 0;
    olibc_retval_t retval;
    olibc_addr_event_listener_t *addr_event_listener;
    olibc_fd_event_listener_info_t fd_event_listener_info;

    if (!addr_event_listener_info || !addr_event_listener_hdl ||
        !addr_event_listener_info->addr_event_listener_cbk ||
        !addr_event_listener_info->flags) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    OLIBC_MALLOC_CHECK(addr_event_listener, sizeof(olibc_addr_event_listener_t),
            __THIS_FUNCTION__, retval);

    addr_event_listener->addr_event_listener_cbk =
        addr_event_listener_info->addr_event_listener_cbk;
    addr_event_listener->args = addr_event_listener_info->args;
    addr_event_listener->flags = addr_event_listener_info->flags;

    if (addr_event_listener_info->flags & OLIBC_FLAG_IPV4) {
        groups |= RTMGRP_IPV4_IFADDR;
    }
    if (addr_event_listener_info->flags & OLIBC_FLAG_IPV6) {
        groups |= RTMGRP_IPV6_IFADDR;
    }

    if (!olibc_nl_sock_init(&addr_event_listener->addr_event_nl_sock_addr,
                NETLINK_ROUTE)) {
        return (OLIBC_RETVAL_FAILED);
    }

    if (!olibc_nl_sock_bind(&addr_event_listener->addr_event_nl_sock_addr,
                             groups)) {
        retval = OLIBC_RETVAL_FAILED;
        goto cleanup;
    }

    memset(&fd_event_listener_info, sizeof(olibc_fd_event_listener_info_t),
            0);
    fd_event_listener_info.fd = addr_event_listener->addr_event_nl_sock_addr.nl_fd;
    fd_event_listener_info.args = addr_event_listener;
    fd_event_listener_info.fd_event_filter = OLIBC_FD_READ;
    fd_event_listener_info.fd_listener_cbk = olibc_addr_event_cbk;
    fd_event_listener_info.pthread_hdl = addr_event_listener_info->pthread_hdl;
    retval =
    olibc_fd_event_listener_create(&addr_event_listener->
                fd_event_listener_hdl,&fd_event_listener_info);
    if(retval != OLIBC_RETVAL_SUCCESS) {
          goto cleanup;
    }
    *addr_event_listener_hdl = addr_event_listener;
    return OLIBC_RETVAL_SUCCESS;

cleanup:
    {
        if(&addr_event_listener->addr_event_nl_sock_addr) {
            olibc_nl_sock_uninit(&addr_event_listener->addr_event_nl_sock_addr);
        }
        if(addr_event_listener) {
            olibc_free((void **)&addr_event_listener);
        }
        return retval;
    }
}

olibc_retval_t
olibc_addr_event_listener_destroy (olibc_addr_event_listener_hdl *addr_event_hdl)
{
    olibc_addr_event_listener_t *addr_event_listener = NULL;

    if (!addr_event_hdl) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    addr_event_listener = *addr_event_hdl;

    olibc_fd_event_listener_destroy(
            &addr_event_listener->fd_event_listener_hdl);

    olibc_nl_sock_uninit(&addr_event_listener->addr_event_nl_sock_addr);

    olibc_free((void **)addr_event_hdl);
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_addr_event_get_iterator (olibc_addr_event_hdl event_hdl,
                               olibc_addr_iterator_hdl *addr_iterator_hdl)
{
    if (!event_hdl || !addr_iterator_hdl) {
        olibc_log_error("\n Invalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    *addr_iterator_hdl = event_hdl->addr_iterator;
    return OLIBC_RETVAL_SUCCESS;
}


olibc_retval_t
olibc_addr_event_get_args (olibc_addr_event_hdl event_hdl, void **args)
{
    if (!event_hdl || !args) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    *args = event_hdl->args;
    return OLIBC_RETVAL_SUCCESS;
}
