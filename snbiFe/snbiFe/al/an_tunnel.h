/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_TUNNEL_H__
#define __AN_TUNNEL_H__

#include "an_types.h"

#define AN_VRF_NAME_BUF_SIZE 32 
#define AN_VRF_NAME "cisco_autonomic"
 
#define AN_VRF_NUM_START 0
#define AN_VRF_NUM_END 2147483647

typedef struct an_vrf_info_t_ {
  uint8_t an_vrf_name[AN_VRF_NAME_BUF_SIZE];   
  uint32_t an_vrf_id;
  uint32_t an_vrf_table_id;
} an_vrf_info_t;

extern an_vrf_info_t an_vrf_info;
#define AN_TUNNEL_NUM_START 100000
#define AN_TUNNEL_NUM_END 2147483647

an_if_t an_tunnel_create(an_addr_t *src, an_addr_t *dst, an_if_t src_if, uint8_t tunn_mode);
void an_tunnel_remove(an_if_t tunn_ifhndl);

boolean an_vrf_define(void);
void an_vrf_remove(void);
boolean an_vrf_configure_interface(an_if_t ifhndl);
boolean an_vrf_unconfigure_interface(an_if_t ifhndl);
void an_vrf_set_name(uint32_t unit);
void an_vrf_set_id(void);
an_vrf_info_t* an_vrf_get(void);
void an_tunnel_init(void);
void an_tunnel_uninit(void);
void an_tunnel_check_integrity(an_if_t tunn_ifhndl, an_if_t tunn_src_ifhndl);
#endif
