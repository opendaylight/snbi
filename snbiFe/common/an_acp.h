/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#ifndef __AN_ACP_H__
#define __AN_ACP_H__

#include "../al/an_types.h"
#include "../al/an_avl.h"
#include "an_msg_mgr.h"
#include "an_nbr_db.h"
#include "an_acp_cnp.h"
#include "an_acp_ntp.h"
#define AN_UNIX_TIME_ACP_RETRY_SECONDS 30

/**************** ACP Client Section *********************/

typedef uint16_t an_acp_client_id_t;
typedef uint8_t* an_acp_client_handle;

typedef enum an_acp_client_id_e_ {
    AN_ACP_CLIENT_ID_CLI = 1,
    AN_ACP_CLIENT_ID_AUTOIP,

    AN_ACP_CLIENT_ID_LIMITER,
} an_acp_client_id_e;

typedef enum an_acp_client_status_e_ {
    AN_ACP_CLIENT_SUCCESS = 1,
    AN_ACP_CLIENT_INVALID_ARGS,          
    AN_ACP_CLIENT_ALREADY_REGD,
    AN_ACP_CLIENT_NOT_REGD,
    AN_ACP_CLIENT_HANDLE_MISMATCH,
    AN_ACP_CLIENT_MEM_FAILURE,
    AN_ACP_CLIENT_DB_FULL,
    AN_ACP_CLIENT_INVALID_IF,
 
    AN_ACP_CLIENT_STATUS_LIMITER,
} an_acp_client_status_e;

extern const uint8_t *
an_acp_client_status_enum_get_string (an_acp_client_status_e enum_type);

typedef enum an_acp_ext_conn_e_ {
    AN_EXT_CONNECT_STATE_NO    =   0,
    AN_EXT_CONNECT_STATE_HOLD  =   1,
    AN_EXT_CONNECT_STATE_DONE  =   2,
} an_acp_ext_conn_e;

typedef struct an_acp_client_comm_t_ an_acp_client_comm_t;
typedef void (*an_acp_client_receive_data)(an_acp_client_comm_t *client_comm);

#define AN_ACP_CLIENT_DESCRIPTION_MAX 20
typedef struct an_acp_client_t_ {
    an_avl_node_t avlnode;

    an_acp_client_id_t id;
    an_acp_client_handle handle;
    an_acp_client_receive_data callback;
    uint8_t description[20];
} an_acp_client_t;

struct an_acp_client_comm_t_ {
    an_acp_client_t client_info;
    an_addr_t dest_addr;
    an_addr_t source_addr;
    an_if_t ifhndl;
    an_payload_t payload;
};

an_acp_client_status_e an_acp_client_send_data(an_acp_client_comm_t *client_comm);
an_acp_client_status_e an_acp_client_register(an_acp_client_t *client_info);
an_acp_client_status_e an_acp_client_unregister(an_acp_client_t *client_info);

void an_acp_client_db_walk(an_avl_walk_f walk_func, void *args);
void an_acp_client_db_init(void);

void an_acp_incoming_message(an_msg_package *acp_message);
void an_vrf_set_name(uint32_t unit);
void an_ikev2_define_profile_names(uint32_t unit);
void an_ikev2_clear_profile_names(void);
void an_ipsec_clear_profile_name(void);

/******************* ACP Setup Section *********************/

#define AN_NO_IPSEC

//ACP Init
void an_acp_init(void);
void an_acp_uninit(void);
void an_acp_uninit_connection(void);
void an_acp_init_connection_device_bootstrapped(void);
void an_acp_init_acp_info_per_nbr_link(an_nbr_link_spec_t *nbr_link_data);
    
//ACP Start
boolean an_acp_start_on_interface(an_if_t ifhndl);

//ACP Create
boolean an_acp_create_to_nbr_for_all_valid_nbr_links(an_nbr_t *nbr);
void an_acp_create_per_nbr_link(an_nbr_t *nbr,
                                an_nbr_link_spec_t *nbr_link_data);
boolean an_acp_create_ipsec_to_nbr_for_all_valid_nbr_links(an_nbr_t *nbr);
an_if_t an_acp_tunnel_create_and_configure(an_addr_t src_ip, an_addr_t dst_ip,
                                   an_if_t ifhndl);

//ACP Remove
boolean an_acp_remove_to_nbr_for_all_valid_nbr_links(an_nbr_t *nbr);
boolean an_acp_remove_per_nbr_link(an_nbr_t *nbr,
                                   an_nbr_link_spec_t *nbr_link_data);
//Autonomic connect command
boolean an_acp_init_external_connection(an_if_t ifhndl);
boolean an_acp_uninit_external_connection(an_if_t ifhndl);
an_acp_ext_conn_e an_acp_connect_state_get(an_if_t ifhndl);
boolean an_acp_hold_external_connection(an_if_t ifhndl);

//ACP Info calls
boolean an_acp_is_initialized(void);
an_if_t an_acp_get_acp_if_on_nbr_link(an_nbr_t *nbr,
                                an_nbr_link_spec_t *nbr_link_data);
boolean an_acp_is_up_on_nbr(an_nbr_t *nbr);
boolean an_acp_is_up_on_nbr_link(an_nbr_link_spec_t *nbr_link_data);
boolean an_acp_channel_is_up_on_nbr_link(an_nbr_link_spec_t *nbr_link_data);
boolean an_acp_security_is_up_on_nbr_link(an_nbr_link_spec_t *nbr_link_data);

void an_acp_routing_enable_on_required_interfaces (an_routing_cfg_t *routing_info);
void an_acp_nbr_link_cleanup(an_nbr_link_context_t *nbr_link_ctx);
void an_acp_register_for_events(void);
#endif


