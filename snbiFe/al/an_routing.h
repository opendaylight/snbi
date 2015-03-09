/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_ROUTING_H__
#define __AN_ROUTING_H__

#include "an_types.h"

#define AN_RPL_DAG_ID \
         {{{0xFD, 0x08, 0x2E, 0xEF, 0xC2, 0xEE, 0x00, 0x00, \
          0x00, 0x00, 0xD2, 0x53, 0x51, 0x85, 0x54, 0x72}}}
extern an_info_t an_info;
extern boolean an_ipv6_unicast_routing_enabled;

void an_rpl_global_enable(an_rpl_info_t *an_rpl_info);
void an_rpl_global_disable(uint8 *tag_name);
void an_rpl_interface_enable(uint8 *tag_name, ulong ifhndl);
void an_rpl_interface_disable(uint8 *tag_name, ulong ifhndl);
void an_acp_routing_init(void);
void an_acp_routing_uninit(void);
void an_acp_routing_enable(an_routing_cfg_t routing_info);
void an_acp_routing_enable_on_interface(an_if_t ifhndl, an_routing_cfg_t routing_info);
void an_acp_routing_disable_on_interface(an_if_t ifhndl, an_routing_cfg_t routing_info);
void an_acp_routing_disable(an_routing_cfg_t routing_info);
void an_set_rpl_routing_info(void);
char *an_get_rpl_tag_name(void);
boolean an_get_rpl_floating_root_enable_flag(void);
void an_rpl_connect_notify_callback(bool sense);
#endif
