
/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <an_types.h>
#include <an.h>
#include <an_mem.h>
#include <an_str.h>
#include <an_logger.h>
#include <an_addr.h>

#define ADDR_IPV6 20 /* IP Version 6 */
#define ADDRLEN_IPV6 16 
#define ADDR_IP 1 
#define ADDRLEN_IP 4 

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
#if 0
#define IN6_IS_ADDR_LINKLOCAL(a)    \
    (((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0x80))

#define IN6_IS_ADDR_SITELOCAL(a)    \
    (((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0xc0))

#define IN6_IS_ADDR_MULTICAST(a)    \
    ((a)->s6_addr8[0] == 0xffU)
#endif
uint8_t an_ipv6_addr_codes[AN_IPV6_MAX_ADDR_CODES];

#define AN_V6_SITELOCAL \
        {{{ 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}}

#define AN_V6_LOOPBACK \
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01} 

#define AN_V6_LL_SCOPE_ALL_NODE_MCAST \
            {0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x50} 

#define AN_ADDR_LOOPBACK \
        {ADDR_IPV6, ADDRLEN_IPV6, AN_V6_LOOPBACK}

uint8_t an_ipv6_addr_codes[AN_IPV6_MAX_ADDR_CODES];

const an_v4addr_t AN_V4ADDR_ZERO = {0};
const an_v6addr_t AN_V6ADDR_ZERO = {{{0}}};
const an_addr_t AN_ADDR_ZERO = {0};

const an_addr_t an_addr_loopback = {.type = ADDR_IPV6,
                                    .length = ADDRLEN_IPV6,
                                    .ipv6_addr = {{AN_V6_LOOPBACK}}};

const an_addr_t an_site_local_prefix = {.type = ADDR_IPV6,
                                .length = ADDRLEN_IPV6,
                                .ipv6_addr = AN_V6_SITELOCAL};

const an_addr_t an_ll_scope_all_node_mcast = {.type = ADDR_IPV6,
                                    .length = ADDRLEN_IPV6,
                                    .ipv6_addr = {{AN_V6_LL_SCOPE_ALL_NODE_MCAST}}};


const an_v6addr_t an_v6addr_loopback = {{AN_V6_LOOPBACK}};
	
void 
an_get_ipv6_group_id_frm_domain (uint8_t *domain_id, uint8_t* group_id)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void 
an_get_ipv6_interface_id_frm_device_id(uint8_t *device_id, 
                                       uint8_t* interface_id)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

inline boolean an_addr_is_v4 (const an_addr_t addr)
{
    return (addr.type == ADDR_IP);
}

inline boolean an_addr_is_v6 (const an_addr_t addr)
{
    return (addr.type == ADDR_IPV6);
}

inline void an_addr_set_from_v6addr (an_addr_t *addr, const an_v6addr_t v6_addr)
{
    memset(addr, 0, sizeof(an_addr_t));
    addr->type = ADDR_IPV6;
    addr->length = ADDRLEN_IPV6;
    memcpy(&addr->ipv6_addr, &v6_addr, ADDRLEN_IPV6);
    return;
}

inline void an_addr_set_from_v4addr (an_addr_t *addr, const an_v4addr_t v4_addr)
{
    memset(addr, 0, sizeof(an_addr_t));
    addr->type = ADDR_IP;
    addr->length = ADDRLEN_IP;
    memcpy(&addr->ip_addr, &v4_addr, ADDRLEN_IP);
    return;
}

inline an_v6addr_t an_addr_get_v6addr (const an_addr_t addr)
{
    if (an_addr_is_v6(addr)) {
        return (addr.ipv6_addr);
    }
    return (AN_V6ADDR_ZERO);
}

an_v6addr_t 
an_addr_ntov6 (uint8_t *buffer)
{
    an_v6addr_t nw_order_v6addr = AN_V6ADDR_ZERO;

    memcpy(&nw_order_v6addr, buffer, sizeof(an_v6addr_t));

    return (nw_order_v6addr);
}

an_v4addr_t 
an_addr_ntov4 (uint8_t *buffer)
{
    return(an_ntoh_4_bytes(buffer));
}

inline an_v4addr_t an_addr_get_v4addr (const an_addr_t addr)
{
    if (an_addr_is_v4(addr)) {
        return (addr.ip_addr);
    }
    return (AN_V4ADDR_ZERO);
}

an_v6addr_t 
an_addr_v6ton (const an_addr_t addr)
{
    an_v6addr_t nw_order_v6addr = AN_V6ADDR_ZERO;

    if (!an_addr_is_v6(addr)) {
        return (AN_V6ADDR_ZERO);
    }

    nw_order_v6addr = addr.ipv6_addr;
    return (nw_order_v6addr);
}

an_v4addr_t 
an_addr_v4ton (const an_addr_t addr)
{
    an_v4addr_t nw_order_v4addr = AN_V4ADDR_ZERO;

    if (!an_addr_is_v4(addr)) {
        return (AN_V4ADDR_ZERO);
    }
    an_hton_4_bytes((uint8_t *)&nw_order_v4addr, addr.ip_addr);

    return (nw_order_v4addr);
}

inline uint8_t an_addr_get_len (const an_addr_t addr)
{
    return (addr.length);
}
#define AN_MAX_ADDR_BUFFS 4
char addr_str_buffs[AN_MAX_ADDR_BUFFS][INET6_ADDRSTRLEN];

// Can be used to only print
inline uint8_t *an_addr_get_string (const an_addr_t *addr)
{
    static uint32_t cnt = 0;
    uint32_t index = cnt % AN_MAX_ADDR_BUFFS;
    char *addr_str_buff = NULL;

    if (!addr) {     
        return (NULL);
    }

    addr_str_buff = addr_str_buffs[index];
    cnt++;

    memset(addr_str_buff, 0, INET6_ADDRSTRLEN);

    if (an_addr_is_v4(*addr)) {
        inet_ntop(AF_INET, &(addr->ip_addr), addr_str_buff, 
                  INET_ADDRSTRLEN);
        return (addr_str_buff);
    } else  if (an_addr_is_v6(*addr)) {
        inet_ntop(AF_INET6, &(addr->ipv6_addr), addr_str_buff, 
                INET6_ADDRSTRLEN);
        return (addr_str_buff);
    } else {
        return NULL;
    }
    return (addr_str_buff);
}

inline int32_t an_addr_struct_comp (const an_addr_t *addr1, const an_addr_t *addr2)
{
    int bytes;
    uchar type;

    if (addr1 == addr2) {
        return (0);
    }
    if (!addr1) {
        return (-1);
    }
    if (!addr2) {
       return (1);
    }
    type = addr1->type ? addr1->type : addr2->type;

    if (type == ADDR_IP) {
        bytes = ADDRLEN_IP;
        return(memcmp(&addr1->ip_addr, &addr2->ip_addr, bytes));
    }
    else {
        bytes = addr1->length ? addr1->length : addr2->length;
        return(memcmp(&addr1->ipv6_addr, &addr2->ipv6_addr, bytes));
    }

    return 0;
}

boolean
an_addr_is_ipv6_linklocal (an_addr_t address)
{
    if (!an_addr_is_v6(address)) {
        return (FALSE);
    }
    return (IN6_IS_ADDR_LINKLOCAL(&address.ipv6_addr));
}

boolean
an_addr_is_ipv6_sitelocal (an_addr_t address)
{
    if (!an_addr_is_v6(address)) {
        return (FALSE);
    }
    return (IN6_IS_ADDR_SITELOCAL(&address.ipv6_addr));
}

boolean
an_addr_is_ipv6_multicast (an_addr_t address)
{
    if (!an_addr_is_v6(address)) {
        return (FALSE);
    }
    return (IN6_IS_ADDR_MULTICAST(&address.ipv6_addr));
}

an_v4addr_t 
an_addr_get_v4addr_from_interface(an_if_t ifhndl) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_V4ADDR_ZERO);
}

void an_addr_set_v4addr_on_interface_and_nvgen (an_if_t ifhndl, an_v4addr_t v4addr, an_v4addr_t v4mask) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

an_v4addr_t 
an_addr_get_v4mask_from_interface(an_if_t ifhndl) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_V4ADDR_ZERO);
}

boolean
an_get_device_base_mac_addr (an_mac_addr chassis_mac[AN_IEEEBYTES])
{
     return TRUE;
}
void
an_str_convert_mac_addr_str_to_hex (const an_mac_addr *macstr, an_mac_addr *buf)
{
}

