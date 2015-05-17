/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_logger.h>
#include <an_if_mgr.h>
#include <an_l2_linux.h>
#include <an_pak.h>
#include <an_str.h>
#include <an_pak_linux.h>
#include <net/if.h>
#include <an_ipv6.h>
#include <an_mem.h>


inline uint8_t* an_pak_get_network_hdr (an_pak_t *pak) 
{   
    if (pak) {
        return ((uint8_t*)&pak->ipv6_hdr);
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
    pak->datagramsize = paklen;
    return;
}

inline void an_pak_set_linktype (an_pak_t *pak, uint8_t linktype)
{
    pak->linktype = linktype;
    return;
}

inline uint8_t 
an_pak_get_linktype (an_pak_t *pak)
{
    if (pak->linktype) {
        return (pak->linktype);
    }
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

uint32_t
an_get_ifhndl_from_sockaddr (struct sockaddr_storage *sender) {

    char ipstr[INET6_ADDRSTRLEN + 1];
    uint32_t sender_port = 0, sender_index = 0;
 
// Deal with both Ipv4 and IPv6 addresses
    if (sender->ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)sender;
        sender_port = ntohs(s->sin_port);
        inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
    }
    else { // AF_INET6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)sender;
        sender_port = ntohs(s->sin6_port);
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
        sender_index = s->sin6_scope_id;
    }

//    printf("Peer IP address: %s    , Port: %d\n", ipstr, sender_port);
//    printf("Sender Index: %d,        Index_name:%s\n", sender_index,index_name);

    return (sender_index);
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

