/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_IPV6_H__
#define __AN_IPV6_H__

#include "an_types.h"

inline boolean an_ipv6_enable_on_interface(an_if_t ifhndl);
inline boolean an_ipv6_disable_on_interface(an_if_t ifhndl);
void an_ipv6_configure_cga_on_interface(an_if_t ifhndl, an_v6addr_t v6addr, 
                uint32_t prefix_len);
void an_ipv6_configure_addr_on_interface(an_if_t ifhndl, an_addr_t addr, 
                uint32_t prefix_len);
void an_ipv6_unconfigure_addr_on_interface(an_if_t ifhndl, an_addr_t addr,
                uint32_t prefix_len);
inline boolean an_ipv6_address_set_unnumbered(an_if_t ifhndl, an_if_t loop_if);
inline an_v6addr_t an_ipv6_get_ll(an_if_t ifhndl);
inline boolean an_ipv6_join_mld_group(an_if_t ifhndl, an_v6addr_t *group_addr);
inline boolean an_ipv6_leave_mld_group(an_if_t ifhndl, an_v6addr_t *group_addr);
inline boolean an_ipv6_preroute_pak (an_pak_t *pak, an_if_t ifhndl, an_addr_t nhop);
inline boolean an_ipv6_forward_pak(an_pak_t *pak);
inline uint16_t an_ipv6_calculate_cksum(const an_ipv6_hdr_t *ipv6_hdr, 
                         const void *ulp_hdr, uint8_t ulp);

an_addr_t an_ipv6_get_best_source_addr(an_addr_t destination, an_iptable_t iptable);
boolean an_ipv6_is_our_address(an_addr_t address, an_iptable_t iptable);

inline boolean an_ipv6_hdr_init(uint8_t *ipv6_hdr, uint8_t tos, uint32_t flow_label, 
        uint16_t payload_len, uint8_t protocol, uint8_t hop_lim,
        an_v6addr_t *source, an_v6addr_t *destination);

inline an_v6addr_t an_ipv6_hdr_get_src(an_ipv6_hdr_t *ipv6_hdr);
inline an_v6addr_t an_ipv6_hdr_get_dest(an_ipv6_hdr_t *ipv6_hdr);
inline uint8_t an_ipv6_hdr_get_version(an_ipv6_hdr_t *ipv6_hdr);
inline uint8_t an_ipv6_hdr_get_next(an_ipv6_hdr_t *ipv6_hdr);
inline uint8_t an_ipv6_hdr_get_hlim(an_ipv6_hdr_t *ipv6_hdr);
inline uint16_t an_ipv6_hdr_get_paylen(an_ipv6_hdr_t *ipv6_hdr);
inline void an_ipv6_hdr_set_paylen(an_ipv6_hdr_t *ipv6_hdr, uint16_t plen);

void an_rwatch_cb(void *app_ctx);
boolean an_rwatch_init(void);
boolean an_rwatch_uninit(void);
void an_rwatch_start_track_ipaddr(an_addr_t ipadr, an_afi_t af, an_iptable_t iptable);
void an_rwatch_stop_track_ipaddr(void);

void an_ipv6_routing_start_global_unicast(void);
void an_ipv6_routing_stop_global_unicast(void);
void an_ipv6_unicast_routing_enable_disable_register(void);
void an_ipv6_unicast_routing_enable_disable_unregister(void);
void an_ipv6_unicast_routing_enable_disable_cb(boolean);


#endif
