/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_ADDR_H__
#define __AN_ADDR_H__

#include "an_types.h"

#define  AN_ADDR_IPV6   ADDR_IPV6
#define  AN_ADDRLEN_IPV6  ADDRLEN_IPV6
#define  AN_ADDR_IP   ADDR_IP
#define  AN_ADDRLEN_IP  ADDRLEN_IP

#define AN_RID_PREFIX { 0x0A010100 }

extern const an_v6addr_t AN_V6ADDR_ZERO;
extern const an_v4addr_t AN_V4ADDR_ZERO;
extern const an_addr_t AN_ADDR_ZERO;

extern const an_v6addr_t an_v6addr_loopback;
extern const an_addr_t an_addr_loopback;

extern const an_v6addr_t an_linklocal_prefix; 
extern const an_addr_t an_ll_scope_all_node_mcast; 

/* Length of IPv6 address */
#define AN_IPV6_INTF_ADDR_LEN 10

/* Max addr codes a-z, 0-9, '-', '_' - each is assigned  6 bit code */
#define AN_IPV6_MAX_ADDR_CODES 128

/* IPv6 address part i.e. SubnetID + Interface ID */
#define AN_IPV6_MAX_ADDR_CODE_LEN   13

/* IPv4 address part i.e. Router ID */
#define AN_IPV4_MAX_ADDR_CODE_LEN   4

/* IPv6 GroupID part size */
#define AN_IPV6_GROUPID_SIZE 5

/* Each code corresponds 6 bits */
#define AN_IPV6_ADDR_CODE_LEN_BITS 6
#define AN_IPV4_ADDR_CODE_LEN_BITS 6

extern uint8_t an_ipv6_addr_codes[AN_IPV6_MAX_ADDR_CODES];

extern const an_addr_t an_site_local_prefix;

inline boolean an_addr_is_v4(const an_addr_t addr);
inline boolean an_addr_is_v6(const an_addr_t addr);
inline void an_addr_set_from_v6addr(an_addr_t *addr, const an_v6addr_t v6_addr);
inline void an_addr_set_from_v4addr(an_addr_t *addr, const an_v4addr_t v4_addr);
inline an_v6addr_t an_addr_get_v6addr(const an_addr_t addr);
inline an_v4addr_t an_addr_get_v4addr(const an_addr_t addr);
an_v6addr_t an_addr_ntov6(uint8_t *buffer);
an_v4addr_t an_addr_ntov4(uint8_t *buffer);
an_v6addr_t an_addr_v6ton(const an_addr_t addr);
an_v4addr_t an_addr_v4ton(const an_addr_t addr);
inline uint8_t an_addr_get_len(const an_addr_t addr);
inline uint8_t * an_addr_get_string(const an_addr_t *addr);
inline int32_t an_addr_comp(const an_addr_t *addr1, const an_addr_t *addr2);
inline int32_t an_addr_struct_comp(const an_addr_t *addr1, const an_addr_t *addr2);
inline boolean an_addr_equal(const an_addr_t *addr1, const an_addr_t *addr2);
inline boolean an_addr_is_zero(const an_addr_t addr);

boolean an_addr_is_ipv6_linklocal(an_addr_t address);
boolean an_addr_is_ipv6_sitelocal(an_addr_t address);
boolean an_addr_is_ipv6_multicast(an_addr_t address);

void an_get_ipv6_group_id_frm_domain(uint8_t *domain_id, uint8_t* group_id);
void an_get_ipv6_interface_id_frm_device_id(uint8_t *device_id, uint8_t* interface_id);
an_addr_t an_get_v6addr_from_names(uint8_t *domain_id, an_mac_addr *macaddress, uint8_t *device_id);
an_v4addr_t an_get_v4addr_from_names(uint8_t *domain_id, uint8_t *device_id);
an_v4addr_t an_addr_get_v4addr_from_interface(an_if_t ifhndl);
an_v4addr_t an_addr_get_v4mask_from_interface(an_if_t ifhndl);
void an_addr_set_v4addr_on_interface_and_nvgen(an_if_t ifhndl, an_v4addr_t v4addr,
                                                              an_v4addr_t mask);
//void an_addr_set_v4addr_on_interface(an_if_t ifhndl, an_v4addr_t v4addr, an_v4addr_t mask);
void an_get_ipv4_router_id_from_device_id(uint8_t *device_id, uint32_t *router_id);
void an_addr_generator_init(void);
#endif
