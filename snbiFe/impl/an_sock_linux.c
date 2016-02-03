/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <olibc_fd_event.h>
#include <olibc_pak.h>
#include <string.h>
#include <an_types.h>
#include <an_logger.h>
#include "an_sock_linux.h"
#include "an_pak_linux.h"
#include <an_msg_mgr.h>
#include "an_proc_linux.h"

int an_sock_fd = 0;
olibc_fd_event_listener_hdl an_sock_fd_event_listener_hdl = NULL;


boolean
an_linux_sock_fd_read_cbk (olibc_fd_event_hdl fd_event_hdl)
{
    int fd;
    olibc_retval_t retval;
    olibc_pak_info_t pak_info;
    olibc_pak_hdl pak_hdl = NULL;
    uint32_t ipv6_udp_offset = 0;
    uint32_t ev_type = 0;

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

    memset(&pak_info, 0, sizeof(olibc_pak_info_t));
    pak_info.addr_family = AF_INET6;

    retval = olibc_pak_create(&pak_hdl, &pak_info);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to create a packet");
        return FALSE;
    }

    ipv6_udp_offset = AN_IPV6_HDR_SIZE + AN_UDP_HDR_SIZE;

    retval = olibc_pak_recv(pak_hdl, fd, ipv6_udp_offset);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        olibc_pak_destroy(&pak_hdl);
        return FALSE;
    }

    if (!an_pak_init_ipv6_udp_hdr(pak_hdl)) {
        olibc_pak_destroy(&pak_hdl);
        return FALSE;
    }

    an_msg_mgr_incoming_message(pak_hdl);
    return TRUE;
}

boolean
an_linux_sock_leave_mld_group (an_if_t ifhndl, an_v6addr_t *group_addr)
{
    struct ipv6_mreq mreq;
    mreq.ipv6mr_multiaddr = *group_addr;
    mreq.ipv6mr_interface = ifhndl;

    if (setsockopt(an_sock_fd, IPPROTO_IPV6,
                   IPV6_LEAVE_GROUP, (char *)&mreq,
                   sizeof(mreq)) != 0) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sFailed to leave mcast group for Ifindex %d", 
                    an_nd_event);
        return FALSE;
    }

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sRemoving the ifindex %d from the multicast group",
                 an_nd_event, ifhndl);
    return TRUE;
}

boolean
an_linux_sock_join_mld_group (an_if_t ifhndl, an_v6addr_t *group_addr)
{
    struct ipv6_mreq mreq;
    mreq.ipv6mr_multiaddr = *group_addr;
    mreq.ipv6mr_interface = ifhndl;

    if (setsockopt(an_sock_fd, IPPROTO_IPV6,
                   IPV6_JOIN_GROUP, (char *)&mreq,
                   sizeof(mreq)) != 0) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sFailed to join mcast group for Ifindex %d", 
                    an_nd_event);
        return FALSE;
    }

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAdding the ifindex %d to the multicast group",
                 an_nd_event, ifhndl);
    return TRUE;
}

boolean
an_linux_sock_init (void)
{
    olibc_retval_t retval;
    struct sockaddr_in6 serv_addr;
    olibc_fd_event_listener_info_t fd_event_listener_info;
    int enable;

    an_sock_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (an_sock_fd < 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
                     "\nSocket Opening failed, exiting..!!");
        return FALSE;
    }

    enable = TRUE;
    if (setsockopt(an_sock_fd, SOL_SOCKET,
                   SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
        "\nFailed to set sock address reuse options");
        return FALSE;
    }

#ifdef SO_REUSEPORT
    enable = TRUE;
    if (setsockopt(an_sock_fd, SOL_SOCKET,
                   SO_REUSEPORT, &enable, sizeof(enable)) < 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
        "\nFailed to set sock port reuse options");
        return FALSE;
    }
#endif

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(AN_UDP_PORT);

    if (bind(an_sock_fd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) != 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
                "\nFailed to bind AN socket");
        return FALSE;
    }

    enable = TRUE;
    if (setsockopt(an_sock_fd, IPPROTO_IPV6,
                   IPV6_RECVPKTINFO, &enable, sizeof(enable)) < 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
        "\nFailed to set RECVPKT options");
        return FALSE;
    }

    enable = FALSE;
    if (setsockopt(an_sock_fd, IPPROTO_IPV6,
                   IPV6_MULTICAST_LOOP, &enable, sizeof(enable)) < 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
        "\nFailed to disable loopback sock ptions");
        return FALSE;
    }
    memset(&fd_event_listener_info, 0, sizeof(olibc_fd_event_listener_info_t));

    fd_event_listener_info.args = NULL;
    fd_event_listener_info.fd = an_sock_fd;
    fd_event_listener_info.pthread_hdl = an_pthread_hdl;
    fd_event_listener_info.fd_event_filter |= OLIBC_FD_READ;
    fd_event_listener_info.fd_listener_cbk = an_linux_sock_fd_read_cbk;

    retval = olibc_fd_event_listener_create(&an_sock_fd_event_listener_hdl, 
                                            &fd_event_listener_info);

    return TRUE;
}
