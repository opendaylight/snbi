/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_types.h"
#include "an.h"
#include "an_mem.h"
#include "an_str.h"
#include "an_logger.h"
#include "an_addr.h"

uint8_t an_ipv6_addr_codes[AN_IPV6_MAX_ADDR_CODES];

const an_v4addr_t AN_V4ADDR_ZERO = {0};
const an_v6addr_t AN_V6ADDR_ZERO = {0};
const an_addr_t AN_ADDR_ZERO = {0};

const an_addr_t an_addr_loopback = {0};

const an_addr_t an_site_local_prefix = {0};
	
const an_addr_t an_ll_scope_all_node_mcast = {0};

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
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

inline boolean an_addr_is_v6 (const an_addr_t addr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

inline void an_addr_set_from_v6addr (an_addr_t *addr, const an_v6addr_t v6_addr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

inline void an_addr_set_from_v4addr (an_addr_t *addr, const an_v4addr_t v4_addr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

inline an_v6addr_t an_addr_get_v6addr (const an_addr_t addr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_V6ADDR_ZERO);
}

an_v6addr_t 
an_addr_ntov6 (uint8_t *buffer)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_V6ADDR_ZERO);
}

an_v4addr_t 
an_addr_ntov4 (uint8_t *buffer)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return(AN_V4ADDR_ZERO);
}

inline an_v4addr_t an_addr_get_v4addr (const an_addr_t addr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_V4ADDR_ZERO);
}

an_v6addr_t 
an_addr_v6ton (const an_addr_t addr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (AN_V6ADDR_ZERO);
}

an_v4addr_t 
an_addr_v4ton (const an_addr_t addr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (AN_V4ADDR_ZERO);
}

inline uint8_t an_addr_get_len (const an_addr_t addr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

inline uint8_t *an_addr_get_string (const an_addr_t *addr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (NULL);
}

inline int32_t an_addr_struct_comp (const an_addr_t *addr1, const an_addr_t *addr2)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

boolean
an_addr_is_ipv6_linklocal (an_addr_t address)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (FALSE);
}

boolean
an_addr_is_ipv6_sitelocal (an_addr_t address)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (FALSE);
}

boolean
an_addr_is_ipv6_multicast (an_addr_t address)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (FALSE);
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
