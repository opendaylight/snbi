/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_ND_H__
#define __AN_ND_H__

#include "../al/an_types.h"
#include "an_msg_mgr.h"
#include "an_nbr_db.h"
#include "../al/an_list.h"
 
#define AN_NBR_LINK_EXPIRE_IMMEDIATE 10

//#define AN_FOR_ALL_DATA_IN_LIST XOS_FOR_ALL_DATA_IN_LIST

#define AN_ND_HELLO 136 
#define AN_ND_OPT 17

#define AN_ND_HELLO_REFRESH_INTERVAL (10*1000)
#define AN_NBR_LINK_CLEAN_INTERVAL (4 * AN_ND_HELLO_REFRESH_INTERVAL)

typedef enum an_nd_oper_e_ {
    AN_ND_OPER_DOWN  =   0,
    AN_ND_OPER_UP    =   1,
} an_nd_oper_e;

typedef enum an_nd_config_state_e_ {
    AN_ND_CFG_DEFAULT  = 0,
    AN_ND_CFG_ENABLED  = 1,
    AN_ND_CFG_DISABLED = 2,
} an_nd_config_state_e;

typedef enum an_nd_client_id_e_ {
    AN_ND_CLIENT_CLI  = 0,
    AN_ND_CLIENT_CONNECT = 1,
    AN_ND_CLIENT_INTERFACE_TYPE = 2,
    AN_ND_CLIENT_MAX,
} an_nd_client_id_e;

typedef struct an_nd_client_t_ {
    an_nd_client_id_e an_nd_client_id;
    an_nd_config_state_e an_nd_state;
} an_nd_client_t;

an_nd_oper_e an_nd_operation_get(an_if_t ifhndl);
boolean an_nd_is_enabled(an_if_t ifhndl);
boolean an_nd_is_operating(an_if_t ifhndl);

boolean an_nd_set_preference(an_if_t ifhndl, an_nd_client_id_e an_nd_client_id,
            an_nd_config_state_e config_state);
an_nd_config_state_e an_nd_get_preference(an_if_t ifhndl, an_nd_client_id_e an_nd_client_id);
an_nd_config_state_e an_nd_state_get (an_if_t ifhndl);

boolean an_nd_start_on_interface(an_if_t ifhndl);
boolean an_nd_stop_on_interface(an_if_t ifhndl);
void an_nd_startorstop (an_if_t ifhndl);
boolean an_nd_init(void);
boolean an_nd_uninit(void);

boolean an_nd_incoming_hello(an_msg_package *msg_package, 
                             an_pak_t *pak, an_if_t ifhndl); 
boolean an_nd_incoming_keep_alive(an_msg_package *msg_package, 
                                  an_if_t ifhndl); 
an_msg_package* an_nd_get_hello(an_if_t ifhndl);


void an_nbr_refresh_hello(void);

//Functions for multiple link to nbr implementation
an_nbr_link_spec_t * an_nbr_update_link_to_nbr(an_msg_package *message, an_nbr_t *nbr,
                                an_if_t local_ifhndl); 
void an_nbr_link_reset_cleanup_timer(an_list_t *an_nbr_link_list,
                                    an_addr_t if_ipaddr, an_if_t ifhndl);
boolean an_nbr_link_init_cleanup_timer(an_nbr_t *nbr, 
                                an_nbr_link_spec_t *nbr_link_data);
void an_nbr_remove_nbr_link(an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data);

boolean an_nbr_walk_link_lost_cb(an_avl_node_t *node, void *args);
boolean an_nd_check_if_nbr_on_valid_link(an_if_t my_ifhndl, 
                                         an_addr_t remote_ipaddr);

#endif
