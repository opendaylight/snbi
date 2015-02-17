/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_IF_MGR_H__
#define __AN_IF_MGR_H__

#include "an_nd.h"
#include "an_acp.h"
#include "../al/an_types.h"
#include "../al/an_logger.h"

typedef enum an_if_type_e_ {
    AN_IF_INVALID = 0,
    AN_IF_L2 = 1,
    AN_IF_L3 = 2,
    AN_IF_L3_POSSIBLE = 3,
    AN_IF_DEFAULT = 4,
} an_if_type_e;

typedef struct an_if_acp_info_t_ {
    boolean is_routing_required;
    an_acp_ext_conn_e ext_conn_state;
}an_if_acp_info_t;

typedef struct an_if_sd_info_t_ {
    an_DNSServiceRef an_syslog_sdRef;
    an_DNSServiceRef an_aaa_sdRef; 
    an_DNSServiceRef an_config_sdRef;
    an_DNSServiceRef an_anr_sdRef;
    an_DNSServiceRef an_autoip_sdRef;
}an_if_sd_info_t;

typedef struct an_if_info_t_ {
    an_avl_node_t avlnode;
    
    an_if_t ifhndl;
    an_cd_oper_e cd_oper;
    an_nd_oper_e nd_oper;
    boolean nd_hello_pending;
    boolean if_cfg_autonomic_enable; //Only for NVGEN management
    boolean if_cfg_autonomic_connect; //Only for NVGEN management
    an_nd_client_t an_nd_client_db[AN_ND_CLIENT_MAX];
    an_nd_config_state_e nd_state;

    uint32_t efp_id;
    an_if_t phy_ifhndl;
    an_if_t vlan_ifhndl;
    an_if_t tunnel_ifhndl;

    /*
     * Internally created by autonomic process
     * and is not expected to managed by user
     */
    boolean autonomically_created;

    an_dot1q_qinq_vlan_id_t vlan_info;
    an_if_acp_info_t an_if_acp_info;
    an_if_sd_info_t an_if_sd_info;

    /*
     * All Channels discovered on this interface
     */
    an_avl_tree an_cd_info_tree;
    an_cd_info_t *an_cd_info_database;
    an_avl_tree an_cd_info_vlan_tree;
    an_cd_info_t *an_cd_info_vlan_database;
    an_if_type_e an_if_type;
    boolean an_reuse_startup_config;
    uint32_t index;

} an_if_info_t;

an_avl_compare_e 
an_if_info_compare(an_avl_node_t *node1, an_avl_node_t *node2);

extern an_if_info_t *an_if_info_database;

void an_if_info_db_init(void);
void an_if_info_db_walk(an_avl_walk_f func, void *args);

an_if_info_t * an_if_info_alloc(void);
void an_if_info_free(an_if_info_t *an_if_info);
boolean an_if_info_db_insert(an_if_info_t *an_if_info);
boolean an_if_info_db_remove(an_if_info_t *an_if_info);
an_if_info_t *an_if_info_db_search(an_if_t ifhndl, boolean alloc);

boolean an_if_is_autonomically_created(an_if_info_t *an_if_info);
boolean an_if_is_autonomic_loopback(an_if_t loopbk_ifhndl); 
boolean an_if_is_autonomic_tunnel(an_if_t tunn_ifhndl);

void an_if_autonomic_disable(an_if_t ifhndl);
void an_if_autonomic_enable(an_if_t ifhndl);

void an_if_set_cfg_autonomic_enable(an_if_info_t *an_if_info, boolean flag);
boolean an_if_is_cfg_autonomic_enabled(an_if_info_t *an_if_info);

void an_if_init(void);
void an_if_uninit(void);
void an_if_bring_up_all(void);
boolean an_should_bring_up_interfaces(void);

boolean an_nd_trigger_hello_on_if(an_if_info_t *an_if_info);

boolean an_if_check_routing_required(an_if_info_t *an_if_info);
boolean an_if_set_routing_required(an_if_info_t *an_if_info);
boolean an_if_unset_routing_required(an_if_info_t *an_if_info);

boolean an_if_platform_specific_media_type_cfg_cb(an_if_t ifhndl, void *data);
#endif
