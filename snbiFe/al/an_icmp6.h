/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_ICMPV6_H__
#define __AN_ICMPV6_H__

#include "an_types.h"

inline uint8_t an_icmp6_get_type(an_icmp6_hdr_t *icmp6_hdr);
inline uint32_t an_icmp6_get_len(an_icmp6_hdr_t *icmp6_hdr, an_ipv6_hdr_t *ipv6_hdr);
inline uint16_t an_icmp6_get_cksum(an_icmp6_hdr_t *icmp6_hdr);
inline void an_icmp6_set_cksum(an_icmp6_hdr_t *icmp6_hdr, uint16_t cksum);
inline void an_icmp6_reset_cksum(an_icmp6_hdr_t *icmp6_hdr);
inline an_ipv6_nd_opt_hdr* an_icmp6_get_an_nd_opt_hdr(an_icmp6_hdr_t *icmp6_hdr, uint32_t icmp_len);

#endif
