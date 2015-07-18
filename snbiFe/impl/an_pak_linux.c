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
#include <an_l2_linux.h>
#include <an_pak_linux.h>
#include <an_proc_linux.h>
#include <olibc_fd_event.h>

int an_sock_fd = 0;
olibc_fd_event_hdl an_sock_fd_event_hdl = NULL;

boolean
an_pak_sock_fd_cbk (int fd, uint32_t ev_type)
{
    olibc_retval_t retval;
    olibc_pak_info_t pak_info;
    olibc_pak_hdl pak_hdl = NULL;

    if (!(ev_type & OLIBC_FD_READ)) {
        return FALSE;
    }

    memset(&pak_info, 0, memset(olibc_pak_info_t));
    pak_info.addr_family = AF_INET6;

    retval = olibc_pak_create(&pak_hdl, &pak_info); 

    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to create a packet");
        return FALSE;
    }

    retval = olibc_pak_recv(pak_hdl, fd,
    return TRUE;
}

void
an_pak_linux_sock_create (void)
{
    olibc_retval_t retval;
    struct ipv6_mreq mreq;
    struct sockaddr_in6 serv_addr;
    olibc_fd_event_info_t fd_event_info;

    an_sock_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (an_sock_fd < 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
                     "\nSocket Opening failed, exiting..!!");
        exit(0);
    }

//    inet_pton(AF_INET6, AN_GROUP, &mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_multiaddr = an_ll_scope_all_node_mcast.ipv6_addr;
    mreq.ipv6mr_interface = 0;

    if (setsockopt(an_sock_fd, IPPROTO_IPV6,
                   IPV6_JOIN_GROUP, (char *)&mreq,
                   sizeof(mreq)) != 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
                "\nFailed to bind AN socket");
        exit(0);
    }

    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(AN_UDP_PORT);

    if (bind(an_sock_fd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) != 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
                "\nFailed to bind AN socket");
        exit(0);
    }

    memset(&fd_event_info, 0, sizeof(olibc_fd_event_info_t));

    fd_event_info.fd = an_sock_fd;
    fd_event_info.fd_event_filter |= OLIBC_FD_READ;
    fd_event_info.pthread_hdl = an_pthread_hdl;
    fd_event_info.fd_event_cbk = an_pak_sock_fd_cbk;

    retval = olibc_fd_event_create(&an_sock_fd_event_hdl, &fd_event_info);
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
    printf("\nTodo set linktype");
    //pak->linktype = linktype;
    return;
}

inline uint8_t 
an_pak_get_linktype (an_pak_t *pak)
{
    printf("\nTodo get linktype");
 //   if (pak->linktype) {
//        return (pak->linktype);
//    }
    return (0);
}

void
an_linux_pak_create (an_pak_t *an_linux_pak, uint32_t ifhndl, char *data, 
                    struct sockaddr_storage *sender)
{
    struct sockaddr_in6 *s = NULL;

    if (!an_linux_pak) {
        return;
    }
    printf("\nTodo an linux pak_create");
#if 0
    an_linux_pak->data = data;
    an_linux_pak->ifhndl = ifhndl;
    
//    an_linux_pak->ipv6_hdr.ip6_src = AN_V6ADDR_ZERO;
//    an_linux_pak->ipv6_hdr.ip6_dst = AN_V6ADDR_ZERO;

    if (sender) {
        s = (struct sockaddr_in6 *)sender;
        an_ipv6_hdr_init((uint8_t *)&an_linux_pak->ipv6_hdr, 
                AN_DEFAULT_TOS, AN_DEFAULT_FLOW_LABEL,
                0, AN_UDP_PROTOCOL, AN_DEFAULT_HOP_LIMIT,
                &s->sin6_addr, &AN_V6ADDR_ZERO);

//        an_linux_pak->ipv6_hdr.ip6_src = s->sin6_addr;
    }
#endif
    return;
}

an_pak_t* an_getbuffer (uint16_t pak_len)
{
    an_pak_t *pak = (an_pak_t *)malloc(sizeof(an_pak_t)); 
    an_linux_pak_create(pak, 0, NULL, NULL); 
    if (pak) { 
        return pak;
    }
    return NULL;
}

inline void an_pak_free (an_pak_t *pak)
{
    if (pak) {
        an_free(pak);
    }
    return;
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

an_pak_t *
an_plat_pak_alloc(uint16_t paklen, an_if_t ifhndl,uint16_t len)
{
    an_pak_t * pak = NULL;
    pak = (an_pak_t *)malloc(sizeof(an_pak_t));
    an_linux_pak_create(pak, ifhndl, NULL, NULL);
    if (!(pak)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, "\n%sMemory Alloc failed "
                      "for pak");
        return (NULL);
    }
    return pak;
}

void
an_cp_msg_block_to_pak (an_pak_t * pak,uint8_t *msg_block,uint8_t
        *temp_msg_block,uint16_t msg_len)
{
//    an_memcpy_s(msg_block, msg_len, temp_msg_block, msg_len);
}

