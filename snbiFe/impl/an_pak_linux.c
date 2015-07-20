/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <an_pak.h>
#include <an_str.h>
#include <net/if.h>
#include <an_ipv6.h>
#include <an_mem.h>
#include <an_types.h>
#include <an_logger.h>
#include <an_if_mgr.h>
#include <olibc_pak.h>
#include "an_l2_linux.h"
#include "an_pak_linux.h"
#include "an_proc_linux.h"
#include <olibc_fd_event.h>
#include <an_udp.h>

int an_sock_fd = 0;
olibc_fd_event_hdl an_sock_fd_event_hdl = NULL;

static boolean 
an_pak_init_ipv6_udp_hdr (olibc_pak_hdl pak_hdl) 
{
    olibc_retval_t retval;
    uint32_t data_length = 0;
    uint8_t *data_buff = NULL;
    uint8_t *udp_hdr = NULL;
    struct sockaddr_storage src_addr, dst_addr;
    struct sockaddr_in6 *s6_src = NULL, *s6_dst = NULL;

    retval = olibc_pak_get_data_buffer(pak_hdl, &data_buff, &data_length);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_PACKET, AN_DEBUG_MODERATE, NULL,
                  "\nFailed to get data buffer");
        return FALSE;
    }

    memset(&src_addr, 0, sizeof(struct sockaddr_storage));
    memset(&dst_addr, 0, sizeof(struct sockaddr_storage));

    retval = olibc_pak_get_src_addr(pak_hdl, &src_addr);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_PACKET, AN_DEBUG_MODERATE, NULL,
                  "\nFailed to get IPv6 Src address");
        return FALSE;
    }

    retval = olibc_pak_get_dst_addr(pak_hdl, &dst_addr);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_PACKET, AN_DEBUG_MODERATE, NULL,
                  "\nFailed to get IPv6 dst address");
        return FALSE;
    }

    if (src_addr.ss_family != AF_INET6 || dst_addr.ss_family != AF_INET6) {
        DEBUG_AN_LOG(AN_LOG_ND_PACKET, AN_DEBUG_MODERATE, NULL,
                "\nInvalid addres family found src_af %d, "
                "dst _af %d",src_addr.ss_family, dst_addr.ss_family);
        return FALSE;
    }

    s6_src = (struct sockaddr_in6 *)&src_addr;
    s6_dst = (struct sockaddr_in6 *)&dst_addr;

    if (!an_ipv6_hdr_init(data_buff,
                AN_DEFAULT_TOS, AN_DEFAULT_FLOW_LABEL,
                data_length, AN_UDP_PROTOCOL, AN_DEFAULT_HOP_LIMIT,
                &s6_src->sin6_addr, &s6_dst->sin6_addr)) {
        DEBUG_AN_LOG(AN_LOG_ND_PACKET, AN_DEBUG_MODERATE, NULL,
                  "\nFailed to init packet header");
        return FALSE;
    }

    udp_hdr = data_buff + AN_IPV6_HDR_SIZE;

    if (an_udp_build_header(data_buff, udp_hdr, AN_UDP_PORT, AN_UDP_PORT,
                data_length - AN_IPV6_HDR_SIZE - AN_UDP_HDR_SIZE)) {
        DEBUG_AN_LOG(AN_LOG_ND_PACKET, AN_DEBUG_MODERATE, NULL,
                "\nFailed to init UDP header");
        return FALSE;
    }

    an_msg_mgr_incoming_message(pak_hdl);

    return TRUE;
}

boolean
an_linux_sock_fd_read_cbk (int fd, uint32_t ev_type)
{
    olibc_retval_t retval;
    olibc_pak_info_t pak_info;
    olibc_pak_hdl pak_hdl = NULL;
    uint32_t ipv6_udp_offset = 0;

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

    return TRUE;
}

boolean
an_linux_sock_create (void)
{
    olibc_retval_t retval;
    struct ipv6_mreq mreq;
    struct sockaddr_in6 serv_addr;
    olibc_fd_event_info_t fd_event_info;
    int enable; 

    an_sock_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (an_sock_fd < 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
                     "\nSocket Opening failed, exiting..!!");
        return FALSE;
    }

//    inet_pton(AF_INET6, AN_GROUP, &mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_multiaddr = an_ll_scope_all_node_mcast.ipv6_addr;
    mreq.ipv6mr_interface = 0;

    if (setsockopt(an_sock_fd, IPPROTO_IPV6,
                   IPV6_JOIN_GROUP, (char *)&mreq,
                   sizeof(mreq)) != 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
                "\nFailed to bind AN socket");
        return FALSE;
    }

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
    if (setsockopt(an_sock_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &enable,
                sizeof(enable)) < 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
                "\nFailed to disable multicast loopback");
        return FALSE;
    }

    memset(&fd_event_info, 0, sizeof(olibc_fd_event_info_t));

    fd_event_info.fd = an_sock_fd;
    fd_event_info.fd_event_filter |= OLIBC_FD_READ;
    fd_event_info.pthread_hdl = an_pthread_hdl;
    fd_event_info.fd_event_cbk = an_linux_sock_fd_read_cbk;

    retval = olibc_fd_event_create(&an_sock_fd_event_hdl, &fd_event_info);
    return TRUE;
}

inline uint8_t* an_pak_get_network_hdr (an_pak_t *pak) 
{   
    if (pak) {
        printf("\nTodo get network hdr");
    }
    return NULL;
}

inline uint8_t* an_pak_get_datagram_hdr (an_pak_t *pak)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

inline uint8_t* an_pak_get_transport_hdr (an_pak_t *pak)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

inline an_if_t an_pak_get_input_if (an_pak_t *pak)
{
    return (0);
}

inline an_if_t an_pak_get_output_if (an_pak_t *pak)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

inline const uint8_t *an_pak_get_input_if_name (an_pak_t *pak)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

inline const uint8_t * an_pak_get_output_if_name (an_pak_t *pak)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (NULL);
}

inline an_iptable_t an_pak_get_iptable (an_pak_t *pak)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

inline void an_pak_set_output_if (an_pak_t *pak, an_if_t output_if)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

inline void an_pak_set_input_if (an_pak_t *pak, an_if_t input_if)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

inline void an_pak_set_iptable (an_pak_t *pak, an_iptable_t iptable)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

inline void an_pak_set_datagram_size (an_pak_t *pak, uint16_t paklen)
{
    printf("\nTodo set datagram size");
//    pak->datagramsize = paklen;
    return;
}

inline void an_pak_set_linktype (an_pak_t *pak, uint8_t linktype)
{
    return;
}

inline uint8_t 
an_pak_get_linktype (an_pak_t *pak)
{
    return (0);
}

inline void an_pak_free (an_pak_t *pak)
{
    if (pak) {
        olibc_pak_destroy(&pak);
    }
    return;
}

an_pak_t *
an_plat_pak_alloc (uint16_t paklen, an_if_t ifhndl, uint16_t len)
{
    olibc_retval_t retval;
    olibc_pak_hdl pak_hdl;
    olibc_pak_info_t pak_info;
    memset(&pak_info, 0, sizeof(olibc_pak_hdl));

    pak_info.addr_family = AF_INET6;
    pak_info.max_pak_length = paklen;
    retval = olibc_pak_create(&pak_hdl, &pak_info);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                "\nPak creation failed");
        return (NULL);
    }

    olibc_pak_set_out_if_index(pak_hdl, ifhndl);

    return pak_hdl;
}

boolean an_pak_grow (an_pak_t **pak_in, uint16_t extra_len)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

an_pak_t *an_pak_duplicate (an_pak_t *pak)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (NULL);
}

inline boolean an_linktype_is_an (uint8_t linktype)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

inline size_t
an_pak_subblock_getsize (an_pak_subblock_index_t idx)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

void an_pak_subblock_setsize(an_pak_subblock_index_t idx, size_t size)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}


void
an_cp_msg_block_to_pak (an_pak_t * pak,uint8_t *msg_block,uint8_t
                        *temp_msg_block,uint16_t msg_len)
{
    an_memcpy_s(msg_block, msg_len, temp_msg_block, msg_len);
}

