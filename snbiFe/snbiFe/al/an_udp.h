/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_UDP_H__
#define __AN_UDP_H__

#include "an_types.h"

typedef uint16_t an_udp_port_t;

boolean an_udp_build_header(uint8_t *iphdr, uint8_t *udp_hdr, 
                    an_udp_port_t dest_port, an_udp_port_t source_port, 
                    uint16_t msg_len);
boolean an_udp_update_checksum(an_pak_t *pak);

#endif
