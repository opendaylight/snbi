/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_types.h"
#include "an_ipv6.h"
#include "an_logger.h"
#include "an_icmp6.h"
#include "an_nd.h"

inline uint8_t 
an_icmp6_get_type(an_icmp6_hdr_t *icmp6)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

/* Gives length of the ICMPv6 message including ICMPv6 Header */
inline uint32_t 
an_icmp6_get_len (an_icmp6_hdr_t *icmp6_hdr, an_ipv6_hdr_t *ipv6_hdr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (0);
}

inline uint16_t
an_icmp6_get_cksum (an_icmp6_hdr_t *icmp6_hdr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

inline void 
an_icmp6_set_cksum (an_icmp6_hdr_t *icmp6_hdr, uint16_t cksum)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

inline void
an_icmp6_reset_cksum (an_icmp6_hdr_t *icmp6_hdr)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

an_ipv6_nd_opt_hdr * 
an_icmp6_get_an_nd_opt_hdr (an_icmp6_hdr_t *icmp6_hdr, uint32_t icmp_len)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return NULL;
}
