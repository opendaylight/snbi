/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_udp.h"
#include "an_ipv6.h"
#include "an_pak.h"
#include "an_msg_mgr.h"

boolean 
an_udp_build_header (uint8_t *ip_block, uint8_t  *udp_block, 
                     an_udp_port_t dest_port, an_udp_port_t source_port, 
                     uint16_t msg_len)
{ 
    an_udp_hdr_t *udp_hdr = NULL;

    if (!udp_block || !ip_block) {
        return (FALSE);
    }

    udp_hdr = (an_udp_hdr_t *)udp_block;

    udp_hdr->source_port = source_port;
    udp_hdr->dest_port = dest_port;
    udp_hdr->length = msg_len + AN_UDP_HDR_SIZE;
    udp_hdr->checksum = an_ipv6_calculate_cksum((an_ipv6_hdr_t *)ip_block,
                                                 udp_hdr, AN_UDP_PROTOCOL);

    return (TRUE);
}

boolean
an_udp_update_checksum (an_pak_t *pak)
{
#if 0
    uint8_t *ip_hdr = NULL, *udp_hdr = NULL;

    if (!pak) {
        return (FALSE);
    }

    ip_hdr = an_pak_get_network_hdr(pak);
    udp_hdr = ip_hdr + AN_IPV6_HDR_SIZE;

    ((an_udp_hdr_t *)udp_hdr)->checksum = 0;
    ((an_udp_hdr_t *)udp_hdr)->checksum =
    an_ipv6_calculate_cksum((an_ipv6_hdr_t *)ip_hdr, udp_hdr, AN_UDP_PROTOCOL);
#endif
    return (TRUE);
 
}
