/*
 * Interface event handler.
 *
 * Anil R <anr2@cisco>
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
 
#include <string.h>
#include <net/if.h>
#include <sys/uio.h>
#include <olibc_log.h>
#include <sys/socket.h>
#include <olibc_common.h>
#include "olibc_rt_netlink.h"
#include "olibc_if_event_internal.h"
#include "olibc_netlink.h"
#include "olibc_if_rt_netlink.h"
#include <event2/event.h>


boolean
olibc_if_event_cbk (olibc_fd_event_hdl fd_event_hdl) 
{
    int fd;
    olibc_retval_t retval;
	struct olibc_if_iterator_t_ *if_iterator;
    uint32_t ev_type = 0;
	olibc_if_event_t if_event;
	olibc_if_event_listener_t *if_event_listener = NULL;
	
	
    if (!fd_event_hdl) {
        return FALSE;
    }

    retval = olibc_fd_event_get_fd(fd_event_hdl, &fd);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }

    retval = olibc_fd_event_get_type(fd_event_hdl, &ev_type);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }

    if (!(ev_type & OLIBC_FD_READ)) {
        return FALSE;
    }

	retval = olibc_fd_event_get_args(fd_event_hdl, (void **) &if_event_listener);
	olibc_if_event_listener_func_t if_event_listener_cbk = if_event_listener->
                                                    if_event_listener_cbk;
	
	
	if (if_event_listener_cbk) {
		OLIBC_MALLOC_CHECK(if_iterator, sizeof(struct olibc_if_iterator_t_),
                       __THIS_FUNCTION__, retval);
		memset(&if_event, 0, sizeof(olibc_if_event_t));
		if_iterator->nl_sock = if_event_listener->if_event_nl_sock_addr;
		if_event.if_iterator = if_iterator;
		if_event.args = if_event_listener->args;
		if_event_listener_cbk(&if_event);
	}
    return TRUE; 
}

olibc_retval_t
olibc_if_event_listener_create (olibc_if_event_listener_info_t 
        *if_event_listener_info, olibc_if_event_listener_hdl 
        *if_event_listener_hdl)
{
	olibc_retval_t retval;
    olibc_if_event_listener_t *if_event_listener = NULL;
	olibc_fd_event_listener_info_t fd_event_listener_info;
	
    if (!if_event_listener_hdl || !if_event_listener_info || 
            !if_event_listener_info->if_event_listener_cbk) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }
	
	
    OLIBC_MALLOC_CHECK(if_event_listener, sizeof(olibc_if_event_listener_t),
                       __THIS_FUNCTION__, retval);
	if_event_listener->if_event_listener_cbk = if_event_listener_info->
        if_event_listener_cbk;
	if_event_listener->args = if_event_listener_info->args;
	
		
	int groups = RTMGRP_LINK;

    if (!olibc_nl_sock_init(&if_event_listener->if_event_nl_sock_addr,
                            NETLINK_ROUTE)) {
        return OLIBC_RETVAL_FAILED;
    }

	if (!olibc_nl_sock_bind(&if_event_listener->if_event_nl_sock_addr, groups)) {
		goto cleanup;
        return OLIBC_RETVAL_FAILED;
    }
	memset(&fd_event_listener_info, sizeof(olibc_fd_event_listener_info_t), 0);

	fd_event_listener_info.fd = if_event_listener->if_event_nl_sock_addr.nl_fd;
	fd_event_listener_info.args = if_event_listener;
	fd_event_listener_info.fd_event_filter = OLIBC_FD_READ;
	fd_event_listener_info.fd_listener_cbk = olibc_if_event_cbk;
	fd_event_listener_info.pthread_hdl = if_event_listener_info->pthread_hdl;
    retval =
        olibc_fd_event_listener_create(&if_event_listener->
                fd_event_listener_hdl,&fd_event_listener_info);
		if(retval != OLIBC_RETVAL_SUCCESS) {
          goto cleanup;
          return retval;
            
		}
	*if_event_listener_hdl = if_event_listener;
    return OLIBC_RETVAL_SUCCESS;
	cleanup: 
	{
		olibc_free((void **)&if_event_listener);
        olibc_nl_sock_uninit(&if_event_listener->if_event_nl_sock_addr);
	}
}

olibc_retval_t
olibc_if_event_listener_destroy (olibc_if_event_listener_hdl *if_event_hdl)
{
    olibc_if_event_listener_t *if_event_listener = NULL;

    if (!if_event_hdl) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if_event_listener = *if_event_hdl;
	
	olibc_fd_event_listener_destroy(&if_event_listener->
                fd_event_listener_hdl);

    olibc_free((void **)if_event_hdl);	

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_if_event_get_if_iterator (olibc_if_event_hdl event_hdl,
                                olibc_if_iterator_hdl *if_iterator_hdl)
{
    if (!event_hdl || !if_iterator_hdl) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    *if_iterator_hdl = event_hdl->if_iterator;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_if_event_get_args (olibc_if_event_hdl event_hdl, void** args)
{
    if (!event_hdl || !args) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    *args = event_hdl->args;
    return OLIBC_RETVAL_SUCCESS;
}
