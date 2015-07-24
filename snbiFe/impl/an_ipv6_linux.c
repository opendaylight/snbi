/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an.h>
#include <an_event_mgr.h>
#include <an_addr.h>
#include <an_logger.h>
#include <an_if.h>
#include <an_tunnel.h>
#include <an_if_mgr.h>
#include <an_acp.h>
#include <an_routing.h>
#include <an_ipv6.h>
#include <netinet/ip6.h>
#include <sys/types.h>
#include <ifaddrs.h>

#define IPV6_FLOWLABEL_MASK     htonl(0x000FFFFF)
#define IPV6_FLOWINFO_MASK      htonl(0x0FFFFFFF)

boolean an_ipv6_unicast_routing_enabled = FALSE;
extern int an_sock_fd;

inline boolean an_ipv6_enable_on_interface (an_if_t ifhndl)
{
    return (TRUE);
}

inline boolean an_ipv6_disable_on_interface (an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

inline boolean an_ipv6_address_set_unnumbered (an_if_t ifhndl, an_if_t unnum_ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (FALSE);
}


void
an_ipv6_configure_addr_on_interface (an_if_t ifhndl, an_addr_t addr, 
                                     uint32_t prefix_len)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_ipv6_configure_cga_on_interface (an_if_t ifhndl, an_v6addr_t v6addr, 
                                    uint32_t prefix_len)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_ipv6_unconfigure_addr_on_interface (an_if_t ifhndl, an_addr_t addr,
                                       uint32_t prefix_len)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

inline an_v6addr_t an_ipv6_get_ll (an_if_t ifhndl)
{
    struct ifaddrs *ifaddr, *ifa;
    struct sockaddr_in6 ip;
    char if_name[IFNAMSIZ];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        freeifaddrs(ifaddr); 
        return (AN_V6ADDR_ZERO);
    }
    if_indextoname(ifhndl, if_name); 
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family != AF_INET6) continue;
        if (strncmp(ifa->ifa_name, if_name, IFNAMSIZ)) continue;
        struct sockaddr_in6 *current_addr = (struct sockaddr_in6 *) ifa->ifa_addr;
        if (!IN6_IS_ADDR_LINKLOCAL(&(current_addr->sin6_addr))) continue;            
            memcpy(&ip, current_addr, sizeof(ip)); 
            freeifaddrs(ifaddr);
            return (ip.sin6_addr); 
    }
    freeifaddrs(ifaddr);
    return (AN_V6ADDR_ZERO);
}

inline boolean an_ipv6_join_mld_group (an_if_t ifhndl, an_v6addr_t *group_addr)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
        "\n%sFailed to add the interface to join the multicast group",
        an_nd_event);
    return (TRUE);
}

inline boolean an_ipv6_leave_mld_group (an_if_t ifhndl, an_v6addr_t *group_addr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

boolean an_ipv6_preroute_pak (an_pak_t *pak, an_if_t ifhndl, an_addr_t nhop)
{
    return (TRUE);
}

boolean an_ipv6_forward_pak (an_pak_t *pak, uint8_t *msg_block,
                             uint32_t *msg_pkg_,uint16_t msgb_len)
{
    olibc_retval_t retval;
    an_addr_t *src, *dst;
    struct sockaddr_in6 src_sock, dst_sock;
    an_msg_package *msg_pkg = (an_msg_package *)msg_pkg_;

    memset(&src_sock, 0, sizeof(struct sockaddr_in6));
    memset(&dst_sock, 0, sizeof(struct sockaddr_in6));

    src    = &(msg_pkg->src);
    dst   = &(msg_pkg->dest);
    retval = olibc_pak_set_out_if_index(pak, msg_pkg->ifhndl);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_PACKET, AN_DEBUG_MODERATE, NULL,
                "\nFailed to set out ifhandle");
        return FALSE;
    }

    src_sock.sin6_port = htons(AN_UDP_PORT);
    dst_sock.sin6_port = htons(AN_UDP_PORT);

    src_sock.sin6_family = AF_INET6;
    dst_sock.sin6_family = AF_INET6;

    src_sock.sin6_addr = src->ipv6_addr;
    dst_sock.sin6_addr = dst->ipv6_addr;

    retval = olibc_pak_set_src_addr(pak, (struct sockaddr *)&src_sock);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_PACKET, AN_DEBUG_MODERATE, NULL,
                "\nFailed to set src socket address");
        return FALSE;
    }

    retval = olibc_pak_set_dst_addr(pak, (struct sockaddr *)&dst_sock);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_PACKET, AN_DEBUG_MODERATE, NULL,
                "\nFailed to set dst socket address");
        return FALSE;
    }

    retval = olibc_pak_send(pak, an_sock_fd, AN_IPV6_HDR_SIZE+AN_UDP_HDR_SIZE);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_PACKET, AN_DEBUG_MODERATE, NULL,
                "\nFailed to send pak");
        return FALSE;
    }
        
    return (TRUE);
}

inline uint8_t an_ipv6_hdr_get_version (an_ipv6_hdr_t *ipv6_hdr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

inline an_v6addr_t an_ipv6_hdr_get_src (an_ipv6_hdr_t *ipv6_hdr)
{
    if(!ipv6_hdr) {
        return AN_V6ADDR_ZERO;
    }
    return (ipv6_hdr->ip6_src);
}

inline an_v6addr_t an_ipv6_hdr_get_dest (an_ipv6_hdr_t *ipv6_hdr)
{
    if(!ipv6_hdr) {
        return AN_V6ADDR_ZERO;
    }
    return (ipv6_hdr->ip6_dst);
}

inline uint8_t an_ipv6_hdr_get_next (an_ipv6_hdr_t *ipv6_hdr)
{
    return (ipv6_hdr->ip6_nxt);
}

inline uint8_t an_ipv6_hdr_get_hlim (an_ipv6_hdr_t *ipv6_hdr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

inline uint16_t an_ipv6_hdr_get_paylen (an_ipv6_hdr_t *ipv6_hdr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

inline void an_ipv6_hdr_set_paylen (an_ipv6_hdr_t *ipv6_hdr, uint16_t plen)
{
     if (ipv6_hdr) {
        ipv6_hdr->ip6_plen = plen;
    }
}

inline uint16_t
an_ipv6_calculate_cksum (const an_ipv6_hdr_t *ipv6_hdr, 
                         const void *ulp_hdr, uint8_t ulp)
{
    return (0);
}

an_addr_t an_ipv6_get_best_source_addr (an_addr_t destination, 
                                        an_iptable_t iptable)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return AN_ADDR_ZERO; 
}

boolean an_ipv6_is_our_address (an_addr_t address, an_iptable_t iptable)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}

inline boolean 
an_ipv6_hdr_init (uint8_t *ipv6_hdr, uint8_t tos, 
                  uint32_t flow_label, uint16_t payload_len, 
                  uint8_t protocol, uint8_t hop_lim,
                  an_v6addr_t *source, an_v6addr_t *destination)
{
    an_ipv6_hdr_t *ipv6_header = NULL;

    if (!ipv6_hdr) {
        return FALSE;
    }
    ipv6_header = (an_ipv6_hdr_t *)ipv6_hdr;
    
    ipv6_header->ip6_flow = 0UL;
    ipv6_header->ip6_vfc |= 0x60; /* version */
    ipv6_header->ip6_flow |= ((tos << 20)
          & (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK));
    ipv6_header->ip6_flow |= (flow_label & IPV6_FLOWLABEL_MASK);
    ipv6_header->ip6_plen = payload_len;
    ipv6_header->ip6_nxt = protocol;
    ipv6_header->ip6_hops = hop_lim;

    if (source) {
        ipv6_header->ip6_src = *source;
    }
    if (destination) {
        ipv6_header->ip6_dst = *destination;
    }

    return TRUE;
}

void *an_rwatch_ctx = NULL;

void
an_rwatch_cb (void *app_ctx)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}

boolean
an_rwatch_init (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}

boolean
an_rwatch_uninit (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}

void
an_rwatch_start_track_ipaddr (an_addr_t ipaddr, an_afi_t af, an_iptable_t iptable)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_rwatch_stop_track_ipaddr (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_ipv6_routing_start_global_unicast (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_ipv6_routing_stop_global_unicast (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_ipv6_unicast_routing_enable_disable_register (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_ipv6_unicast_routing_enable_disable_unregister (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

an_list_t* 
an_ipv6_get_list_of_ipv6_addresses_on_interface (an_if_t ifhndl) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return NULL;
}

void 
an_ipv6_clean_all_v6addr_on_interface (an_list_t *list, an_if_t ifhndl) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void 
an_ipv6_set_and_clean_v6addr_on_interface_and_nvgen (an_list_t *list, an_if_t ifhndl) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}
