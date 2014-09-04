/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_IF_H__
#define __AN_IF_H__

#include "an_types.h"
#include "../common/an_if_mgr.h"
#include "../common/an_cd.h"

extern uint32_t an_loopback_id;
typedef boolean (*an_if_walk_func)(an_if_t ifhndl, void *data);
inline const uint8_t* an_if_get_name(an_if_t ifhndl);
inline const uint8_t* an_if_get_short_name(an_if_t ifhndl);
inline boolean an_if_is_tunnel(an_if_t ifhndl);
inline boolean an_if_is_loopback(an_if_t ifhndl);
inline boolean an_if_is_up(an_if_t ifhndl);
boolean an_if_make_volatile(an_if_t ifhndl);
void an_if_walk(an_if_walk_func func, void *data);
void an_if_init(void);
void an_if_uninit(void);
void an_if_services_init(void);
void an_if_services_uninit(void);
void an_if_enable(void);
void an_if_disable(void);
boolean an_if_is_ethernet(an_if_t ifhndl);
an_if_t an_if_check_vlan_exists(uint32_t unit);
boolean an_if_check_loopback_exists(uint32_t unit);
boolean an_if_bring_up(an_if_t ifhndl);
an_if_t an_if_create_loopback(uint32_t unit);
void an_if_start_channel_on_all(void);
an_if_t an_get_autonomic_loopback_ifhndl(void);

void an_if_remove_loopback (an_if_t lb_ifhndl);
an_idbtype * an_if_loopback_recycle_idb (void);
an_idbtype * an_if_number_to_swidb(an_if_t ifhndl);
void clear_idb_subblocks (an_idbtype *idb);
boolean an_if_recycle_matcher (an_idbtype *idb);
void an_if_platform_specific_cfg(an_if_t ifhndl);
void an_platform_specific_init(void);
uint8_t* an_if_get_l2_mac_addr(an_hwidbtype *hwidb);
void an_if_set_svi_mac_addr(an_hwidbtype *hwidb, uint8_t* l2_mac);
boolean an_if_is_layer2(an_if_t ifhndl);
void an_l2_nd_trigger_hello(an_if_t ifhndl, boolean request, an_dot1q_qinq_vlan_id_t *vlan_sb, an_udi_t *dest_udi);
void an_l2_disable_channel(an_if_t ifhndl, an_cd_info_t *an_cd_info);
boolean an_l2_check_probe_possible(an_if_t ifhndl);
void an_l2_reuse_startup_config(an_if_t ifhndl);
boolean an_cd_start_probing_on_interface_cb(an_if_t ifhndl, void *data);
void an_cd_start_probing_on_interfaces(void);
an_walk_e an_cd_refresh_probe_cb(an_avl_node_t *node, void *data);
boolean an_should_bring_up_interfaces(void);
inline void an_set_if_vlanid(an_if_info_t *an_if_info, ushort vlanid);
inline void an_set_if_inner_vlanid(an_if_info_t *an_if_info, ushort inner_vlanid);  


#endif
