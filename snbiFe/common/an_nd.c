/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "../al/an_addr.h"
#include "../al/an_cert.h"
#include "../al/an_ether.h"
#include "../al/an_if.h"
#include "../al/an_icmp6.h"
#include "../al/an_ipv6.h"
#include "../al/an_ipv6_nd.h"
#include "../al/an_ipv6_send.h"
#include "../al/an_sudi.h"
#include "../al/an_pak.h"
#include "../al/an_types.h"
#include "../al/an_timer.h"
#include "../al/an_logger.h"
#include "../al/an_mem.h"
#include "../al/an_str.h"
#include "../al/an_misc.h"
#include "an.h"
#include "an_nd.h"
#include "an_nbr_db.h"
#include "an_event_mgr.h"
#include "an_if_mgr.h"
#include "an_anra.h"
#include "an_ni.h"
#include "../al/an_tunnel.h"
#include "../al/an_list.h"
//#include "../ios/an_parse_ios.h"
#include "../al/an_ntp.h"
#include "an_cd.h"

an_timer an_nd_hello_timer;
uint16_t an_nd_if_count = 0;
an_nd_oper_e an_nd_global_oper = AN_ND_OPER_DOWN;
an_nd_config_state_e an_nd_global_state = AN_ND_CFG_DEFAULT;

extern an_avl_tree an_nbr_tree;
extern an_avl_walk_e an_nbr_db_uninit_cb(an_avl_node_t *node, void *args);

an_msg_package *
an_nd_get_keep_alive_msg_package (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data);
static an_cerrno an_nbr_link_lost_cb(an_list_t *list,
        const an_list_element_t *current,
        an_list_element_t *next, void *context);
an_nd_client_t an_nd_global_client_db[AN_ND_CLIENT_MAX] = {
                        {AN_ND_CLIENT_CLI, AN_ND_CFG_DEFAULT},
                        {AN_ND_CLIENT_CONNECT, AN_ND_CFG_DEFAULT},
                        {AN_ND_CLIENT_INTERFACE_TYPE, AN_ND_CFG_DEFAULT}};
an_avl_compare_e an_nbr_compare(an_avl_node_t *node1, an_avl_node_t *node2);
extern an_cd_info_t *
an_cd_info_db_search_udi_only(an_if_info_t *an_phy_info, 
                              an_cd_info_t *goal_an_cd_info);

void
an_nd_set_client_db_init (an_if_info_t *an_if_info)
{
    uint16_t nd_client;

    if(!an_if_info) {
        for (nd_client = AN_ND_CLIENT_CLI; nd_client < AN_ND_CLIENT_MAX; nd_client++) {
            an_nd_global_client_db[nd_client].an_nd_client_id = nd_client;
            an_nd_global_client_db[nd_client].an_nd_state = AN_ND_CFG_DEFAULT;
        }

        return;
    }

    for (nd_client = AN_ND_CLIENT_CLI; nd_client < AN_ND_CLIENT_MAX; nd_client++) {
        an_if_info->an_nd_client_db[nd_client].an_nd_client_id = nd_client;
        an_if_info->an_nd_client_db[nd_client].an_nd_state = AN_ND_CFG_DEFAULT;
    }

    return;
}

an_nd_oper_e
an_nd_operation_get (an_if_t ifhndl)
{
    an_if_info_t *an_if_info = NULL;

    if (!ifhndl) {
        /* Global */
        return (an_nd_global_oper);
    } else {
        /* Interface Level */
        an_if_info = an_if_info_db_search(ifhndl, FALSE);
        if (!an_if_info) {
            return (AN_ND_OPER_DOWN);
        }
        return (an_if_info->nd_oper);
    }
}

an_nd_config_state_e
an_nd_state_get (an_if_t ifhndl)
{
    an_if_info_t *an_if_info = NULL;

    if (!ifhndl) {
        return an_nd_global_state;
    } else {
        an_if_info = an_if_info_db_search(ifhndl, FALSE);
        if (an_if_info) {
            return an_if_info->nd_state;
        }
    }

    return AN_ND_CFG_DEFAULT;
}

an_nd_config_state_e
an_nd_compute_state (an_if_t ifhndl)
{
    an_if_info_t *an_if_info = NULL;
    an_nd_config_state_e nd_cfg_state = AN_ND_CFG_DEFAULT;
    an_nd_client_id_e nd_client = AN_ND_CLIENT_CLI;

    if (!ifhndl) {
        for (nd_client = AN_ND_CLIENT_CLI; nd_client < AN_ND_CLIENT_MAX;
                    nd_client++) {
            if (AN_ND_CFG_DISABLED == an_nd_global_client_db[nd_client].an_nd_state) {
                return (AN_ND_CFG_DISABLED);
            }

            if (AN_ND_CFG_ENABLED == an_nd_global_client_db[nd_client].an_nd_state) {
                nd_cfg_state = AN_ND_CFG_ENABLED;
            }

        }

        return (nd_cfg_state);
    } else {
        an_if_info = an_if_info_db_search(ifhndl, FALSE);
        if (an_if_info) {
            for (nd_client = AN_ND_CLIENT_CLI; nd_client < AN_ND_CLIENT_MAX; 
                    nd_client++) {
                if (AN_ND_CFG_DISABLED == an_if_info->an_nd_client_db[nd_client].an_nd_state) {
                    return (AN_ND_CFG_DISABLED);
                }

                if (AN_ND_CFG_ENABLED == an_if_info->an_nd_client_db[nd_client].an_nd_state) {
                    nd_cfg_state = AN_ND_CFG_ENABLED;
                }

            }
        }
    }

    return (nd_cfg_state);
}

boolean
an_nd_is_enabled (an_if_t ifhndl)
{
    an_nd_config_state_e nd_state;

    nd_state = an_nd_state_get(ifhndl);
    
    return ((nd_state == AN_ND_CFG_DEFAULT) || 
                (nd_state == AN_ND_CFG_ENABLED));
}

boolean
an_nd_is_operating (an_if_t ifhndl)
{
    an_nd_oper_e nd_oper = AN_ND_OPER_DOWN;

    nd_oper = an_nd_operation_get(ifhndl);

    return (nd_oper == AN_ND_OPER_UP);
}

boolean
an_nd_set_preference (an_if_t ifhndl, an_nd_client_id_e client_id,
                            an_nd_config_state_e state)
{
    an_if_info_t *an_if_info = NULL;

    if ((client_id < AN_ND_CLIENT_CLI) || (client_id >= AN_ND_CLIENT_MAX) ||
                (state < AN_ND_CFG_DEFAULT) || (state > AN_ND_CFG_DISABLED)) {
                return (FALSE);
    }

    if (!ifhndl) {
        /* Global */
        an_nd_global_client_db[client_id].an_nd_state = state;
        an_nd_global_state = an_nd_compute_state(ifhndl);
        //an_nd_init();
    } else {
        /* Interface Level */
        an_if_info = an_if_info_db_search(ifhndl, FALSE);
        if (!an_if_info) {
            return (FALSE);
        } else {
            an_if_info->an_nd_client_db[client_id].an_nd_state = state;
            an_if_info->nd_state = an_nd_compute_state(ifhndl);
        }
    }
    return (TRUE);
}

an_nd_config_state_e 
an_nd_get_preference (an_if_t ifhndl, an_nd_client_id_e client_id)
{
    an_if_info_t *an_if_info = NULL;

    if ((client_id < AN_ND_CLIENT_CLI) || (client_id >= AN_ND_CLIENT_MAX)) {
        return AN_ND_CFG_DEFAULT;
    }

    if (!ifhndl) {
        return an_nd_global_client_db[client_id].an_nd_state;
    } else {
        an_if_info = an_if_info_db_search(ifhndl, FALSE);
        if (!an_if_info) {
            return (AN_ND_CFG_DEFAULT);
        }

        return an_if_info->an_nd_client_db[client_id].an_nd_state;
    } 
}

void
an_nd_startorstop (an_if_t ifhndl)
{
    if (!ifhndl) {
        if (AN_ND_CFG_ENABLED == an_nd_state_get(ifhndl)) {
            an_nd_init();
        } else if (AN_ND_CFG_DISABLED == an_nd_state_get(ifhndl)) {
            an_nd_uninit();
        }
        return;
    }
    
    if (AN_ND_CFG_ENABLED == an_nd_state_get(ifhndl)) {
        an_nd_start_on_interface(ifhndl);
    } else if (AN_ND_CFG_DISABLED == an_nd_state_get(ifhndl)) {
        an_nd_stop_on_interface(ifhndl);
    }    
}

boolean
an_nd_start_on_interface (an_if_t ifhndl)
{
    uint8_t *sudi_keypair_label = NULL;
    an_if_info_t *an_if_info = NULL;
	an_v6addr_t an_ll_scope_all_node_mcast_v6addr = AN_V6ADDR_ZERO;

    if (an_if_is_loopback(ifhndl)) {
        return (FALSE);
    }

    an_if_info = an_if_info_db_search(ifhndl, TRUE);
    if (!an_if_info) {
        return (FALSE);
    }

    if (!an_nd_is_enabled(0)) {
        an_if_info->nd_oper = AN_ND_OPER_DOWN;
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNeighbor Discovery not enabled globally", 
                     an_nd_event); 
        return (FALSE);
    }

    if (!an_nd_is_enabled(an_if_info->ifhndl)) {
        an_if_info->nd_oper = AN_ND_OPER_DOWN;
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNeighbor Discovery not enabled on the interface %s",
                     an_nd_event, an_if_get_name(ifhndl));
        return (FALSE);
    }

    if (an_nd_is_operating(an_if_info->ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNbr Discovery already running on the interface %s",
                     an_nd_event, an_if_get_name(ifhndl));
        return (TRUE);
    }

    if (!an_if_is_up(ifhndl)) {
        an_if_info->nd_oper = AN_ND_OPER_DOWN;
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                      "\n%sInterface %s not UP to start Nbr Discovery on it",
                      an_nd_event, an_if_get_name(ifhndl));
        return (TRUE);
    }

    if (an_if_set_and_get_type(ifhndl, AN_IF_INVALID, FALSE) == AN_IF_L2) {
        an_if_info->nd_oper = AN_ND_OPER_DOWN;
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                      "\n%sInterface %s is an L2 interface hence not starting " 
                      "Neighbor Discovery on it", an_nd_event, 
                      an_if_get_name(ifhndl));

        return (TRUE);
    }

    if (!an_sudi_get_keypair_label(&sudi_keypair_label)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sSudi keypair label doesn't exist", an_nd_event);
    }

    if (!an_ipv6_enable_on_interface(ifhndl)) {
        return (FALSE);
    }

    if (an_nd_delivery == AN_ND_DELIVERY_IPV6_ND) {
        if (an_if_info->an_if_acp_info.ext_conn_state == 
                                    AN_EXT_CONNECT_STATE_DONE) {
            an_ipv6_send_init_on_interface_with_secmode_transit(ifhndl, 
                        sudi_keypair_label);
        } else {
            an_ipv6_send_init_on_interface(ifhndl, sudi_keypair_label);
        }
    }

	an_ll_scope_all_node_mcast_v6addr = 
					an_addr_get_v6addr(an_ll_scope_all_node_mcast);
    an_ipv6_join_mld_group(ifhndl, 
                           (an_v6addr_t *)&an_ll_scope_all_node_mcast_v6addr);
    an_if_info->nd_oper = AN_ND_OPER_UP;


    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sEnabled Nbr Discovery on the interface %s", an_nd_event,
                 an_if_get_name(ifhndl));

    an_nd_trigger_hello_on_if(an_if_info);

    return (TRUE);
}


boolean
an_nd_stop_on_interface (an_if_t ifhndl)
{
    uint8_t *sudi_keypair_label = NULL;
    an_if_info_t *an_if_info = NULL;
	an_v6addr_t an_ll_scope_all_node_mcast_v6addr = AN_V6ADDR_ZERO;

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sDisabling Nbr Discovery on an interface %s", an_nd_event, 
                 an_if_get_name(ifhndl));

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
        return (FALSE);
    }
    if (an_if_set_and_get_type(ifhndl, AN_IF_INVALID, FALSE) == AN_IF_L2) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sInterface %s is an L2 interface hence Stopping VTI",
                     an_nd_event, an_if_get_name(ifhndl)); 
        return (TRUE);
    }

    if (!an_nd_is_operating(an_if_info->ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNbr Discovery already dormant on the interface %s",
                     an_nd_event, an_if_get_name(ifhndl));
        return (TRUE);
    }

    if (!an_sudi_get_keypair_label(&sudi_keypair_label)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sSudi keypair label doesn't exist", an_nd_event);
    }

    if (an_nd_delivery == AN_ND_DELIVERY_IPV6_ND) {
        an_ipv6_send_uninit_on_interface(ifhndl, sudi_keypair_label); 
    }
    
    an_if_info->nd_oper = AN_ND_OPER_DOWN;

    an_ipv6_disable_on_interface(ifhndl);

	an_ll_scope_all_node_mcast_v6addr = 
					an_addr_get_v6addr(an_ll_scope_all_node_mcast);
    an_ipv6_leave_mld_group(ifhndl, 
                            (an_v6addr_t *)&an_ll_scope_all_node_mcast_v6addr);

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sDisabled Nbr Discovery on the interface %s", an_nd_event, 
                 an_if_get_name(ifhndl)); 

    return (TRUE);
}

boolean
an_nd_stop_on_interface_cb (an_if_t ifhndl, void *data)
{
    an_nd_stop_on_interface(ifhndl);
    return (TRUE);
}

void
an_nd_stop_on_interfaces (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "%sStoping Nbr Discovery on all interfaces", an_nd_event);
    an_if_walk(an_nd_stop_on_interface_cb, NULL);
}


boolean
an_nd_activate_interface_cb (an_if_t ifhndl, void *data)
{
    an_if_info_t *an_if_info = NULL;
    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
        return (TRUE);
    }

    if (AN_ND_CFG_ENABLED == an_nd_state_get(ifhndl)) { 
        an_event_interface_activated(an_if_info);
    }

    return (TRUE);
}

void
an_nd_activate_interfaces (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "%sStarting Nbr Discovery on all interfaces", an_nd_event);
    an_if_walk(an_nd_activate_interface_cb, NULL);
}

boolean
an_nd_init (void)
{
    an_cerrno rc = EOK;
    uint8_t *sudi_keypair_label = NULL;

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sInitiating Neighbor Discovery globally", an_nd_event);
	
    if (!an_nd_is_enabled(0)) {
        return (FALSE);
    }

    if (an_nd_is_operating(0)) {
        return (TRUE);
    }

    an_sudi_get_keypair_label(&sudi_keypair_label);
    if (!sudi_keypair_label) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sSudi KeyPair Label doesn't exist, " 
                     "while initializing Nbr Discovery", an_nd_event);
    }

    if (an_nd_delivery == AN_ND_DELIVERY_IPV6_ND) {
        an_ipv6_send_init(sudi_keypair_label, AN_IPV6_SEND_SEC_LEVEL, 
                           AN_IPV6_SEND_ITERATIONS);
        an_ipv6_nd_attach(); 
    }

    an_timer_init(&an_nd_hello_timer, AN_TIMER_TYPE_HELLO_REFRESH, NULL, FALSE);
    an_timer_start(&an_nd_hello_timer, AN_ND_HELLO_REFRESH_INTERVAL);

    an_nd_global_oper = AN_ND_OPER_UP;

    rc = an_avl_init(&an_nbr_tree, an_nbr_compare);
    if (CERR_IS_NOTOK(rc)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
              "\n%sAN ND NBR DB Init Failed", an_nd_event);
    }

    an_nd_activate_interfaces();
    return (TRUE);
}

boolean
an_nd_uninit ()
{
    uint8_t *sudi_keypair_label = NULL;
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sUn-Initializing Neighbor_Discovery Globally", 
                 an_nd_event);

    if (!an_nd_is_operating(0)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sND already dormant globally while un-initializing " 
                     "Nbr Discovery", an_nd_event);
        return (TRUE);
    }

    an_nd_stop_on_interfaces();
    an_avl_uninit(&an_nbr_tree, an_nbr_db_uninit_cb);

    an_sudi_get_keypair_label(&sudi_keypair_label);
    if (!sudi_keypair_label) {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                     "%sSudi KeyPair Label doesn't exist, " 
                     "while un-initializing Nbr Discovery", an_nd_db);
    }

    if (an_nd_delivery == AN_ND_DELIVERY_IPV6_ND) {
        an_ipv6_send_uninit(sudi_keypair_label);
        an_ipv6_nd_detach(); 
    }

    an_nd_global_oper = AN_ND_OPER_DOWN;

    an_timer_stop(&an_nd_hello_timer);

    return (TRUE);
}

boolean
an_nd_trigger_hello_on_if_over_udp (an_if_info_t *an_if_info)
{
    an_v6addr_t v6addr = AN_V6ADDR_ZERO;
    an_msg_package *msg_package = NULL;
    int indicator = 0;

    if (!an_if_info) {
        return (FALSE);
    }

    v6addr = an_ipv6_get_ll(an_if_info->ifhndl);    
    an_memcmp_s(&v6addr, sizeof(an_v6addr_t), (void *)&AN_V6ADDR_ZERO, 
                                           sizeof(an_v6addr_t), &indicator);
    if (!indicator) {
        return (TRUE);
    }     

    //DEBUG_AN_LOG(AN_LOG_ND_PACKET, AN_DEBUG_MODERATE, NULL,
    //             "\n%sTriggering Hello on interface %s", an_nd_pak, 
    //             an_if_get_name(an_if_info->ifhndl));
    
    msg_package = an_nd_get_hello(an_if_info->ifhndl);
    an_msg_mgr_send_message(msg_package);

    return (TRUE);
}

boolean
an_nd_trigger_hello_on_if_over_ipv6_nd (an_if_info_t *an_if_info)
{
    an_v6addr_t v6addr = AN_V6ADDR_ZERO;
    int indicator = 0;

    if (!an_if_info) {
        return (FALSE);
    }

    v6addr = an_ipv6_get_ll(an_if_info->ifhndl);    
    an_memcmp_s(&v6addr, sizeof(an_v6addr_t), (void *)&AN_V6ADDR_ZERO, 
                                           sizeof(an_v6addr_t), &indicator);
    if (!indicator) {
        return (TRUE);
    }

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sTriggering Hello on interface %s", an_nd_event, 
                 an_if_get_name(an_if_info->ifhndl));

    an_if_info->nd_hello_pending = TRUE;
    an_ipv6_nd_trigger_unsolicited_na(&v6addr, an_if_info->ifhndl);

    return (TRUE);
}

boolean
an_nd_trigger_hello_on_if (an_if_info_t *an_if_info)
{
    if (!an_if_info) {
        return (FALSE);
    }

    if (!an_if_is_up(an_if_info->ifhndl)) {
        return (TRUE);
    }     

    if (!an_nd_is_operating(an_if_info->ifhndl)) {
        return (TRUE);
    }

    if (an_nd_delivery == AN_ND_DELIVERY_IPV6_ND) {
        an_nd_trigger_hello_on_if_over_ipv6_nd(an_if_info);

    } else if (an_nd_delivery == AN_ND_DELIVERY_UDP) {
        an_nd_trigger_hello_on_if_over_udp(an_if_info);
    }
    return (TRUE);
}

boolean 
an_nd_trigger_keep_alive_per_nbr_link (an_nbr_t *nbr, 
                                       an_nbr_link_spec_t *nbr_link_data)
{
    an_msg_package *msg_package = NULL;
    if (!nbr || !nbr_link_data) {
        return (FALSE);
    }
    
    if (an_acp_is_up_on_nbr_link(nbr_link_data)) {
        msg_package = an_nd_get_keep_alive_msg_package(nbr, nbr_link_data);
        an_msg_mgr_send_message(msg_package);
        return (TRUE);
    }
    return (FALSE);
}   

boolean
an_nd_trigger_keep_alive_per_all_nbr_links (an_nbr_t *nbr) 
{
    an_list_element_t *elem = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    int i = 0;

    AN_FOR_ALL_DATA_IN_LIST(nbr->an_nbr_link_list, elem, nbr_link_data) {
        if (nbr_link_data != NULL) {
            i++;
            an_nd_trigger_keep_alive_per_nbr_link(nbr, nbr_link_data);
        }
    }
    return (TRUE);
}

an_avl_walk_e	
an_nd_trigger_hello_cb (an_avl_node_t *node, void *data)
{
    an_if_info_t *an_if_info = NULL;

    if (!node) {
        return (AN_AVL_WALK_FAIL);
    }
    an_if_info = (an_if_info_t *)node;

    an_nd_trigger_hello_on_if(an_if_info);

    an_thread_check_and_suspend();
    return (AN_AVL_WALK_SUCCESS);
}

an_avl_walk_e
an_nd_trigger_keep_alive_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    
    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }
    
    if (!an_ni_is_nbr_inside(nbr)) {
        return (AN_AVL_WALK_FAIL);
    }
    
    if (an_acp_is_up_on_nbr(nbr)) {
        an_nd_trigger_keep_alive_per_all_nbr_links(nbr);
    }
    return (AN_AVL_WALK_SUCCESS);
}

void
an_nbr_refresh_hello ()
{

    if (!an_nd_is_operating(0)) {
        return;
    }

    an_if_info_db_walk(an_nd_trigger_hello_cb, NULL);
    an_nbr_db_walk(an_nd_trigger_keep_alive_cb, NULL); 
    an_timer_start(&an_nd_hello_timer, AN_ND_HELLO_REFRESH_INTERVAL);
}

an_nbr_t *
an_nd_convert_message_to_nbr (an_msg_package *message)
{
    an_nbr_t *nbr = NULL;
    an_udi_t empty_udi = {};
    
    if (!message) {
        return (NULL);
    }

    nbr = an_nbr_alloc();    

    if (!nbr) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                     "\n%s Memory allocation failed to nbr", an_nd_event);
        return (NULL);
    }

    nbr->iptable = message->iptable; 

    nbr->udi = message->udi;
    message->udi = empty_udi;

    nbr->device_id = message->device_id; 
    message->device_id = NULL;

    nbr->domain_id = message->domain_id;
    message->domain_id = NULL; 

    nbr->device_ipaddr = message->device_ipaddr;
    message->device_ipaddr = AN_ADDR_ZERO;
    return (nbr);
}

/* return TRUE if params changed */
an_msg_interest_e
an_nbr_check_params (an_msg_package *message, an_nbr_t *nbr,
                     an_if_t local_ifhndl,
                     an_nbr_link_spec_t *link_data)
{
    an_msg_interest_e changed = 0;
    int indicator1 = 0;
    int indicator2 = 0;

    if (!message || !nbr) {
        return (changed);
    }
    an_memcmp_s(message->device_id, AN_STR_MAX_LEN, 
                nbr->device_id, an_strlen(nbr->device_id), &indicator1);
    if ((an_strlen(message->device_id) != an_strlen(nbr->device_id)) ||
        (indicator1)) {
        AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_ID);
    }

    an_memcmp_s(message->domain_id, AN_STR_MAX_LEN, 
                nbr->domain_id, an_strlen(nbr->domain_id), &indicator2);

    if ((an_strlen(message->domain_id) != an_strlen(nbr->domain_id)) ||
        (indicator2)) {
        AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DOMAIN_ID);
    }

    if (an_memcmp(&message->device_ipaddr, &nbr->device_ipaddr,
                   sizeof(an_addr_t))) {
       AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_IPADDR);
    }

    if (!nbr->an_nbr_link_list) { 
        /* something is wrong, should not reach here */
        return(changed);
    }
     
     if (!link_data) {        
         DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                      "\n%sSearch failed for the link[%s] in the Nbr Link DB "
                      "and Nbr detected on this new link", 
                      an_nd_db, an_if_get_name(local_ifhndl));        
         AN_SET_BIT_FLAGS(changed, AN_MSG_INT_NEW_NBR_LINK);

     } else {
         DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_INFO, NULL, 
                      "\n%sLink[%s] already exists in the Nbr link DB, "
                      "- recieved Hello Msg on the previously detected link", 
                      an_nd_db, an_if_get_name(local_ifhndl));
     }

    return (changed);
}

void
an_nd_nbr_params_changed (an_nbr_t *nbr, an_msg_interest_e changed)
{
    if (!nbr || !changed) {
        return;
    }

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sNbr params", an_nd_event)
    if (AN_CHECK_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_ID) ||
        AN_CHECK_BIT_FLAGS(changed, AN_MSG_INT_DOMAIN_ID)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_INFO, NULL,
                     " %s%s  changed, trigger cert request to Nbr [%s]",
                     AN_CHECK_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_ID) ?
                     "[device_id]" : "",
                     AN_CHECK_BIT_FLAGS(changed, AN_MSG_INT_DOMAIN_ID) ?
                     ", [domain_id]" : "", nbr->udi.data);

        an_event_nbr_params_changed(nbr);
    }
}


boolean
an_nbr_update_params (an_msg_package *message,
                      an_nbr_t *nbr,
                      an_if_t local_ifhndl,
                      an_nbr_link_spec_t *link_data,
                      an_msg_interest_e new_nbr_link_flag)
{
    an_msg_interest_e changed = 0;
    int indicator1 = 0;
    int indicator2 = 0;

    if (!message || !nbr) {
        return (FALSE);
    }

    nbr->iptable = message->iptable;
    
    if (!message->device_id && 
        (an_strlen(message->device_id) != an_strlen(nbr->device_id))) {
        
        AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_ID);

        if (nbr->device_id) {
            an_free_guard(nbr->device_id);
            nbr->device_id = NULL;
        }
    }
     
    if (!message->domain_id && 
        (an_strlen(message->domain_id) != an_strlen(nbr->domain_id))) {

        AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DOMAIN_ID);

        if (nbr->domain_id) {
            an_free_guard(nbr->domain_id);
            nbr->domain_id = NULL;
        }
    }
    an_memcmp_s(message->device_id, AN_STR_MAX_LEN, 
                nbr->device_id, an_strlen(nbr->device_id), &indicator1);

    if (message->device_id && 
        ((an_strlen(message->device_id) != an_strlen(nbr->device_id)) ||
         (indicator1))) {

        AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_ID);

        if (nbr->device_id) {
            an_free_guard(nbr->device_id);
            nbr->device_id = NULL;
        }
        if (message->device_id && an_strlen(message->device_id)) {
            nbr->device_id = (uint8_t *)an_malloc_guard(
                           an_strlen(message->device_id)+1, "AN MSG device id");
            if (!nbr->device_id) {
                return (FALSE);
            }
            an_memcpy_guard_s(nbr->device_id, an_strlen(message->device_id)+1,
                            message->device_id,
                           an_strlen(message->device_id)+1);
        }
    }
    an_memcmp_s(message->domain_id, AN_STR_MAX_LEN,
                nbr->domain_id, an_strlen(nbr->domain_id), &indicator2);

    if (message->domain_id && 
        ((an_strlen(message->domain_id) != an_strlen(nbr->domain_id)) ||
         (indicator2))) {

        AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DOMAIN_ID);

        if (nbr->domain_id) {
            an_free_guard(nbr->domain_id);
            nbr->domain_id = NULL;
        }
        if (message->domain_id && an_strlen(message->domain_id)) {
            nbr->domain_id = (uint8_t *)an_malloc_guard(
                             an_strlen(message->domain_id)+1,
                             "AN MSG domain id");
            if (!nbr->domain_id) {
                return (FALSE);
            }
            an_memcpy_guard_s(nbr->domain_id, an_strlen(message->domain_id)+1,
                        message->domain_id, an_strlen(message->domain_id)+1);
        }
    }

    if (an_memcmp(&message->device_ipaddr, &nbr->device_ipaddr,
                   sizeof(an_addr_t))) {
        AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_IPADDR);
        nbr->device_ipaddr = message->device_ipaddr;
    }

    if (AN_CHECK_BIT_FLAGS(new_nbr_link_flag, AN_MSG_INT_NEW_NBR_LINK)) {
        link_data = an_nbr_update_link_to_nbr(message, nbr, local_ifhndl);
    }

    if (changed) {
        if (an_acp_is_up_on_nbr(nbr)) { 
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%s Nbr Params changed when ACP is up on the nbr," 
                            " hence ignore the message", an_nd_event); 
            return (FALSE);
        }
        an_nd_nbr_params_changed(nbr, changed);
    } 
    
    link_data->last_refreshed_time=
                             an_unix_time_get_current_timestamp(); 
    an_event_nbr_refreshed(nbr, link_data);
    return (TRUE);
}

an_nbr_link_spec_t *
an_nbr_update_link_to_nbr (an_msg_package *message,
                           an_nbr_t *nbr,
                           an_if_t local_ifhndl)
{
    boolean success  = FALSE;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    /*
     * Link IP Address is different hence create a 
     * interface list for this neighbor
    */
    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sNbr seen on new link %s, add link to "
                 "Nbr Link DB", an_nd_db, an_if_get_name(local_ifhndl)); 
    an_syslog(AN_SYSLOG_NBR_ADDED, nbr->udi.data,an_if_get_name(local_ifhndl));
    nbr_link_data = an_nbr_link_db_alloc_node();
    if (nbr_link_data == NULL)
    {
       DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
      "\n%sMalloc for Nbr Link data failed, not updating Nbr Link DB", an_nd_db);
       return (NULL);
    }

    success = an_nbr_link_db_insert(nbr->an_nbr_link_list, nbr_link_data,
                                      local_ifhndl,
                                      message->if_ipaddr, message->if_name);
    if (success == FALSE)
    {
       DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                    "\n%sNew link Insertion to the Nbr link DB failed, "
                    "hence freeing the nbr [%s] on link %s", 
                    an_nd_db, nbr->udi.data, an_if_get_name(local_ifhndl));
       if (nbr_link_data->nbr_if_name) {
           an_free_guard(nbr_link_data->nbr_if_name);
       }
       an_free_guard(nbr_link_data);
       return (NULL);
    }
      if (!an_nbr_link_init_cleanup_timer(nbr, nbr_link_data)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT,  AN_DEBUG_MODERATE, NULL,
                "\n%s Nbr Link Cleanup Initiation Failed", an_nd_event);
        return (NULL);
    }
    nbr->num_of_links = nbr->num_of_links + 1;

    an_event_nbr_link_add(nbr, nbr_link_data);
    nbr_link_data->added_time =
                  an_unix_time_get_current_timestamp();
    nbr_link_data->keep_alive_received = FALSE; 

    return (nbr_link_data);
}

boolean channel_exist = FALSE;

boolean
an_nd_incoming_keep_alive (an_msg_package *message, an_if_t tunn_ifhndl) 
{
    an_nbr_t *nbr = NULL;
    an_list_element_t *elem = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;

    nbr = an_nbr_db_search(message->udi);
    
    if (!nbr) {
        return (FALSE);
    }
    
    if (!an_acp_is_initialized()) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%s,ACP not initialised, not supposed to receive"
                     " Keep Alive message", an_nd_event);
        return (FALSE);
    }

    
    AN_FOR_ALL_DATA_IN_LIST(nbr->an_nbr_link_list, elem, nbr_link_data) {
        if (tunn_ifhndl == nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.ifhndl) {
            nbr_link_data->keep_alive_received = TRUE;
            an_timer_reset(&nbr_link_data->cleanup_timer,
                           AN_NBR_LINK_CLEAN_INTERVAL);
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sResetting Timer Type [Nbr Per Link Cleanup] for the "
                         "Nbr Link DB entry %s", an_nd_event, an_if_get_name(tunn_ifhndl));
            break;
        } 
    }
    an_msg_mgr_free_message_package(message);
    return (TRUE);
}

boolean
an_nd_incoming_hello (an_msg_package *message, an_pak_t *pak,  
                      an_if_t local_ifhndl)
{
    an_nbr_t *nbr = NULL;
	an_udi_t my_udi = {};
    boolean res = FALSE;
    an_if_info_t *an_if_info;
    an_msg_interest_e changed = 0;
    an_nbr_link_spec_t *nbr_link_data = NULL;
	int indicator = 0;
    an_if_info = an_if_info_db_search(local_ifhndl, FALSE);

    if (!pak || !message || !local_ifhndl || !an_if_info) {
        an_msg_mgr_free_message_package(message);
        return (FALSE);
    }

    if (!message->udi.data || !message->udi.len) {
        an_msg_mgr_free_message_package(message);
        return (FALSE);
    }

    if (!an_nd_is_operating(message->ifhndl)) {
        an_msg_mgr_free_message_package(message); 
        return (FALSE);
    }
    
    if (!an_get_udi(&my_udi)) {
        an_msg_mgr_free_message_package(message);
        return (FALSE);
    }  
    
    an_memcmp_s(my_udi.data, AN_UDI_MAX_LEN, message->udi.data, 
                message->udi.len, &indicator);
    if(!indicator) {
       an_msg_mgr_free_message_package(message);
       return (FALSE);
    }

    //Check if the remote LL addr and my LL addr are different
    //If same, drop the HELLO
    if (!an_nd_check_if_nbr_on_valid_link(local_ifhndl, message->if_ipaddr)) {
        an_msg_mgr_free_message_package(message); 
        return (FALSE);
    }

    nbr = an_nbr_db_search(message->udi);
    if (nbr) {
        nbr_link_data = an_nbr_link_db_search(nbr->an_nbr_link_list,
                                              local_ifhndl,
                                              message->if_ipaddr);
        if (nbr_link_data != NULL && nbr_link_data->keep_alive_received == TRUE) {
            an_msg_mgr_free_message_package(message);
            return (FALSE);
        }

        changed = an_nbr_check_params(message, nbr, local_ifhndl, nbr_link_data);

        if (changed) {
           an_nbr_update_params(message, nbr, local_ifhndl, nbr_link_data, changed);

        } else {
            DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                         "\n%sNeighbor [%s] entry already exists in Nbr DB, "
                         "refreshing the Nbr in Nbr DB", 
                         an_nd_db, nbr->udi.data);    
            nbr_link_data->last_refreshed_time=
                                 an_unix_time_get_current_timestamp(); 
            an_event_nbr_refreshed(nbr, nbr_link_data);
        }

    } else {
		if (AN_ND_CFG_ENABLED != an_nd_get_preference(an_if_info->ifhndl, AN_ND_CLIENT_CLI)) {
            if (!an_cd_does_channel_exist_to_nbr(message)) {
                DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                        "\n%sNbr[%s] Not found in the L2 data base"
                        "(Not directly connected) hence not creating Adjacency",
                        an_nd_db, message->udi.data)
                    an_msg_mgr_free_message_package(message);
                return (FALSE);
            }
        }
         /*
         * Create a New Neighbor
         */
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNbr[%s] not found in Nbr DB, hence creating new nbr",
                     an_nd_db, message->udi.data)
        nbr = an_nd_convert_message_to_nbr(message);
        if (!nbr) {
            return (FALSE);
        }
        
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                    "\n%sNew nbr found on interface %s, Remote Interface %s "
                    "from IPaddr %s", an_nd_event, an_if_get_name(local_ifhndl), 
                    message->if_name, an_addr_get_string(&message->if_ipaddr));

        if (an_nbr_link_db_create(nbr)) {
            nbr_link_data = an_nbr_link_db_alloc_node();
            if (nbr_link_data == NULL)
            {
                DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                            "\n%sMemory alloc failed for the Nbr link data, "
                             "hence Nbr link [%s] not inserted in the "
                             "Nbr link DB", an_nd_db, 
                             an_if_get_name(local_ifhndl));
                an_nbr_free(nbr);
                an_msg_mgr_free_message_package(message);
                return (FALSE);
            }
            res = an_nbr_link_db_insert(nbr->an_nbr_link_list, nbr_link_data,
                        local_ifhndl, message->if_ipaddr,
                        message->if_name);
            if (res == FALSE)
            {
                DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                       "\n%sInsertion of Nbr link %s to Nbr Link DB failed, " 
                       "hence freeing the memory allocated for nbr link data", 
                        an_nd_db, an_if_get_name(local_ifhndl));
                if (nbr_link_data->nbr_if_name) {
                    an_free_guard(nbr_link_data->nbr_if_name);
                }
                an_free_guard(nbr_link_data);
                an_nbr_free(nbr);
                an_msg_mgr_free_message_package(message);
                return (FALSE);
            }            
            if (!an_nbr_link_init_cleanup_timer(nbr, nbr_link_data)) {
                DEBUG_AN_LOG(AN_LOG_ND_EVENT,  AN_DEBUG_MODERATE, NULL,
                        "\n%s Nbr Link Cleanup Initiation Failed", an_nd_event);
                an_nbr_free(nbr);
                an_msg_mgr_free_message_package(message);
                return (FALSE);
            }
            nbr->num_of_links = nbr->num_of_links + 1;
            nbr_link_data->added_time =
                         an_unix_time_get_current_timestamp();
        } else {
            DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                         "%sNbr [%s] Link DB creation failed, "
                         "not able to add the nbr to Nbr DB", an_nd_db, 
                         nbr->udi.data);
            an_nbr_free(nbr);
            an_msg_mgr_free_message_package(message);
            return (FALSE);
        }

        an_nbr_db_insert(nbr);
        an_event_nbr_add(nbr);
    }

    an_nbr_link_reset_cleanup_timer(nbr->an_nbr_link_list, 
                                    message->if_ipaddr, local_ifhndl);
    an_msg_mgr_free_message_package(message);
    return (TRUE);
}

an_msg_package *
an_nd_get_keep_alive_msg_package (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data) 
{
    an_msg_package *message = NULL;
    an_v6addr_t v6addr = AN_V6ADDR_ZERO; 
    an_udi_t udi = {};
    uint8_t *if_name = NULL;
    an_cert_t domain_device_cert = {};
    an_addr_t device_ip;
    
    message = an_msg_mgr_get_empty_message_package();
    if (!message) {
        return (NULL);
    }    

    an_msg_mgr_init_header(message, AN_PROTO_ADJACENCY_DISCOVERY, 
                           AN_MSG_ND_KEEP_ALIVE);

    message->ifhndl = nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.ifhndl;
    an_addr_set_from_v6addr(&message->src, an_ipv6_get_ll(message->ifhndl)); 
    message->dest = an_ll_scope_all_node_mcast;

    if (!an_get_udi(&udi)) {
        an_msg_mgr_free_message_package(message);
        return (NULL);
    }
 
    if (udi.len) {
        message->udi.data = (uint8_t *)an_malloc_guard(udi.len, "AN MSG UDI");
        if (!message->udi.data) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        }
        message->udi.len = udi.len;
        an_memcpy_guard_s(message->udi.data, udi.len, udi.data, udi.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);
    }

    if (an_get_domain_cert(&domain_device_cert)) {
        message->device_id = (uint8_t *)an_malloc_guard(
                1+an_strlen(an_get_device_id()), "AN MSG Device ID");
        if (!message->device_id) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        }
        an_memcpy_guard_s(message->device_id, 1+an_strlen(an_get_device_id()), 
                     an_get_device_id(), 1+an_strlen(an_get_device_id()));
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DEVICE_ID);

        message->domain_id = (uint8_t *)an_malloc_guard(
                1+an_strlen(an_get_domain_id()), "AN MSG Domain ID");
        if (!message->domain_id) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        }
        an_memcpy_guard_s(message->domain_id, 1+an_strlen(an_get_domain_id()), 
                     an_get_domain_id(), 1+an_strlen(an_get_domain_id()));
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DOMAIN_ID);

        device_ip = an_get_device_ip();
        if (!an_addr_is_zero(device_ip)) {
            message->device_ipaddr = an_get_device_ip();
            AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DEVICE_IPADDR);
        }

    }

    v6addr = an_ipv6_get_ll(nbr_link_data->local_ifhndl);
    an_addr_set_from_v6addr(&message->if_ipaddr, v6addr); 
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_IF_IPADDR);

    if_name = (uint8_t *)an_if_get_name(message->ifhndl);
    message->if_name = (uint8_t *)an_malloc_guard(1+an_strlen(if_name), 
                                  "AN MSG IF Name");
    if (!message->if_name) {
        an_msg_mgr_free_message_package(message);
        return (NULL);
    }
    an_memcpy_guard_s(message->if_name, 1+an_strlen(if_name), if_name, 
                                                1+an_strlen(if_name));
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_IF_NAME);
    
    return (message);

}

an_msg_package *
an_nd_get_hello (an_if_t ifhndl)
{
    an_msg_package *message = NULL;
    an_v6addr_t v6addr = AN_V6ADDR_ZERO; 
    an_udi_t udi = {};
    uint8_t *if_name = NULL;
    an_cert_t domain_device_cert = {};
    an_addr_t device_ip;
    
    message = an_msg_mgr_get_empty_message_package();    
    if (!message) {
        return (NULL);
    }    

    an_msg_mgr_init_header(message, AN_PROTO_ADJACENCY_DISCOVERY, 
                           AN_ADJACENCY_DISCOVERY_HELLO);

    message->ifhndl = ifhndl;
    an_addr_set_from_v6addr(&message->src, an_ipv6_get_ll(message->ifhndl)); 
    message->dest = an_ll_scope_all_node_mcast;

    if (!an_get_udi(&udi)) {
        an_msg_mgr_free_message_package(message);
        return (NULL);
    }
 
    if (udi.len) {
        message->udi.data = (uint8_t *)an_malloc_guard(udi.len, "AN MSG UDI");
        if (!message->udi.data) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        }
        message->udi.len = udi.len;
        an_memcpy_guard_s(message->udi.data, udi.len, udi.data, udi.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);
    }

    if (an_get_domain_cert(&domain_device_cert)) {
        message->device_id = (uint8_t *)an_malloc_guard(
                1+an_strlen(an_get_device_id()), "AN MSG Device ID");
        if (!message->device_id) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        }
        an_memcpy_guard_s(message->device_id, 1+an_strlen(an_get_device_id()), 
                     an_get_device_id(), 1+an_strlen(an_get_device_id()));
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DEVICE_ID);

        message->domain_id = (uint8_t *)an_malloc_guard(
                1+an_strlen(an_get_domain_id()), "AN MSG Domain ID");
        if (!message->domain_id) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        }
        an_memcpy_guard_s(message->domain_id, 1+an_strlen(an_get_domain_id()), 
                     an_get_domain_id(), 1+an_strlen(an_get_domain_id()));
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DOMAIN_ID);

        device_ip = an_get_device_ip();
        if (!an_addr_is_zero(device_ip)) {
            message->device_ipaddr = an_get_device_ip();
            AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DEVICE_IPADDR);
        }

    }

    v6addr = an_ipv6_get_ll(ifhndl);
    an_addr_set_from_v6addr(&message->if_ipaddr, v6addr); 
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_IF_IPADDR);

    if_name = (uint8_t *)an_if_get_name(ifhndl);
    message->if_name = (uint8_t *)an_malloc_guard(1+an_strlen(if_name), 
                                  "AN MSG IF Name");
    if (!message->if_name) {
        an_msg_mgr_free_message_package(message);
        return (NULL);
    }
    an_memcpy_guard_s(message->if_name, 1+an_strlen(if_name), if_name, 
                                                1+an_strlen(if_name));
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_IF_NAME);

    return(message);
}

boolean
an_nbr_link_init_cleanup_timer (an_nbr_t *nbr,
                                an_nbr_link_spec_t *nbr_link_data)
{
    an_nbr_link_context_t *link_ctx = NULL;

    //Timer Context
    link_ctx = an_malloc_guard(sizeof(an_nbr_link_context_t),
                                      "AN Interface Context");
    if (link_ctx == NULL) {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n% Mem alloc failed for nbr link timer context, " 
                     "freeing Nbr [%s] link data", an_nd_db, nbr->udi.data);
        if (nbr_link_data->nbr_if_name) {
           an_free_guard(nbr_link_data->nbr_if_name);
        }
        an_free_guard(nbr_link_data);
        return FALSE;
    }

    link_ctx->nbr = nbr;
    link_ctx->nbr_link_data = nbr_link_data;

    DEBUG_AN_LOG(AN_LOG_ND_EVENT,  AN_DEBUG_MODERATE, NULL, 
                 "\n%s Nbr Link Cleanup Initiated", an_nd_event);
    an_timer_init(&nbr_link_data->cleanup_timer,
                  AN_TIMER_TYPE_PER_NBR_LINK_CLEANUP, link_ctx, FALSE);
    an_timer_start(&nbr_link_data->cleanup_timer, AN_NBR_LINK_CLEAN_INTERVAL);
    return TRUE;
}

void
an_nbr_link_reset_cleanup_timer (an_list_t *list,
                                   an_addr_t if_ipaddr, an_if_t ifhndl)
{
    an_nbr_link_spec_t *nbr_link_data = NULL;

    if (!list)
    {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNull INPUT param- Nbr link DB, hence can't reset " 
                     "cleanup timer", an_nd_db);
        return;
    }
    nbr_link_data = an_nbr_link_db_search(list, ifhndl, if_ipaddr);
    if (nbr_link_data != NULL)
    {
       an_timer_reset(&nbr_link_data->cleanup_timer,
                               AN_NBR_LINK_CLEAN_INTERVAL);
       DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                    "\n%sResetting Timer Type [Nbr Per Link Cleanup] for the "
                    "Nbr Link DB entry %s", an_nd_event, an_if_get_name(ifhndl));
    }else {
       DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                    "\n%sFailed to reset cleanup timer for link %s", 
                    an_nd_event, an_if_get_name(ifhndl));
    }

}

static an_cerrno
an_nbr_link_lost_cb (an_list_t *list,
        const an_list_element_t *current,
        an_list_element_t *next, void *context)
{
    an_nbr_link_context_t *if_data = NULL;
    an_nbr_link_spec_t *curr_data = NULL;
    an_nbr_link_context_t link_info;

    if_data = (an_nbr_link_context_t *) context;
    if (current == NULL || if_data == NULL)    {
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }
    curr_data = (an_nbr_link_spec_t *) current->data;
    if (if_data->nbr_link_data->local_ifhndl == curr_data->local_ifhndl) {
          link_info.nbr = if_data->nbr; 
          link_info.nbr_link_data = curr_data;
          an_acp_nbr_link_cleanup(&link_info);
          an_nd_nbr_link_cleanup_event_handler(&link_info);
    }
  
   return (AN_CERR_SUCCESS);
}

an_avl_walk_e
an_nbr_walk_link_lost_cb (an_avl_node_t *node, void *args)
{
   an_nbr_t *nbr = (an_nbr_t *)node;
   an_if_t *ifhndl = (an_if_t *)args;
   an_nbr_link_spec_t nbr_link_data;
   an_nbr_link_context_t nbr_link;
   an_cerrno ret;
   
   if (!nbr || !args) {
      return (AN_AVL_WALK_FAIL);
   }
   
   nbr_link_data.local_ifhndl = *ifhndl;
   nbr_link.nbr_link_data = &nbr_link_data;
   nbr_link.nbr = nbr;
   ret = an_nbr_link_db_walk(nbr->an_nbr_link_list, an_nbr_link_lost_cb, 
                             &nbr_link);
   
   return (AN_AVL_WALK_SUCCESS);
}

void
an_nbr_remove_nbr_link (an_nbr_t *nbr, an_nbr_link_spec_t* nbr_link_data)
{
    if (!nbr || !nbr_link_data) {
       DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                    "\n%sNULL Input Params, Can't remove the Nbr Link data", 
                    an_nd_db);
       return;
    }

    an_nbr_link_db_remove(nbr->an_nbr_link_list, nbr_link_data);
    an_nbr_link_db_free_node(nbr_link_data);

    if (nbr->num_of_links > 0) {
        nbr->num_of_links = nbr->num_of_links -1;
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sRemaining Links after Nbr[%s] link removal [%d]", 
                     an_nd_db, nbr->udi.data, nbr->num_of_links);
    }
}

boolean
an_nd_check_if_nbr_on_valid_link (an_if_t my_ifhndl,  an_addr_t remote_ipaddr)
{
    an_addr_t my_ll_addr = AN_ADDR_ZERO;
    int indicator = 0;

    an_addr_set_from_v6addr(&my_ll_addr,
                            an_ipv6_get_ll(my_ifhndl));

    an_memcmp_s(&my_ll_addr, sizeof(an_addr_t), &remote_ipaddr, 
                                           sizeof(an_addr_t), &indicator);
    //My ll addr and remote nbr ll address are same- DONT accept this ND Hello
    //indicator = 0 : means both address are same
    if (!indicator) {
        return (FALSE);
    }

    return (TRUE);
}

/*-------------------------AN ND event handlers -------------------------*/
void
an_nd_interface_down_event_handler (void *if_info_ptr)
{
    an_if_info_t *an_if_info = NULL;
    an_if_t *ifhndl_info, ifhndl;

    if(!if_info_ptr) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle interface event ");
        return;
    }
    ifhndl_info = (an_if_t *)if_info_ptr;
    ifhndl = *ifhndl_info;

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
        return;
    }
    an_event_interface_deactivated(ifhndl);
}

void
an_nd_interface_up_event_handler (void *if_info_ptr)
{
    an_if_info_t *an_if_info = NULL;
    an_if_t *ifhndl_info, ifhndl;

    if(!if_info_ptr) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle interface event ");
        return;
    }
    ifhndl_info = (an_if_t *)if_info_ptr;
    ifhndl = *ifhndl_info;

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
        return;
    }
    /*
     * On autonomically created or configured interfaces start Adjacency discovery
     */
    if ((an_if_info->autonomically_created) ||
        (AN_ND_CFG_ENABLED == an_nd_state_get(ifhndl))) {
        an_event_interface_activated(an_if_info);
        return ;
    }
}

void
an_nd_interface_activate_event_handler (void *if_info_ptr)
{
    an_if_info_t *an_if_info = NULL;
    an_if_t *ifhndl_info, ifhndl;

    if(!if_info_ptr) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle interface Activate event ");
        return;
    }
    ifhndl_info = (an_if_t *)if_info_ptr;
    ifhndl = *ifhndl_info;
    an_if_info = an_if_info_db_search(ifhndl, FALSE);

    if (!an_if_info) {
        return;
    }

    if (an_nd_is_operating(ifhndl)) {
        return;
    }

    an_nd_start_on_interface(ifhndl);
    return;
}

void
an_nd_interface_deactivate_event_handler (void *if_info_ptr)
{
    an_if_t *ifhndl_info, ifhndl;

    if(!if_info_ptr) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle interface Deactivate event ");
        return;
    }
    ifhndl_info = (an_if_t *)if_info_ptr;
    ifhndl = *ifhndl_info;
    an_nd_stop_on_interface(ifhndl);
}

void
an_nd_hello_refresh_timer_expired_event_handler (void *info_ptr)
{
    an_nbr_refresh_hello();
}

void an_nd_nbr_add_event_handler (void *nbr_info_ptr)
{
    an_if_t nbr_ifhndl = 0;
    an_nbr_t *nbr = NULL;

    if(!nbr_info_ptr) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle nbr add event ");
        return;
    }
    nbr = (an_nbr_t *)nbr_info_ptr;
    
    if (!nbr || !nbr->udi.data) {
        return;
    }

    if (!an_nbr_get_addr_and_ifs(nbr, NULL, &nbr_ifhndl, NULL)) {
        return;
    }

    an_syslog(AN_SYSLOG_NBR_ADDED,
             nbr->udi.data,an_if_get_name(nbr_ifhndl));

    an_nbr_refresh_hello();
}

void
an_nd_remove_and_free_nbr (an_nbr_t *nbr)
{
     if (an_nbr_link_db_is_empty(nbr))
     {
         //If all the interfaces to this nbr are down- expire the nbr entry
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_INFO, NULL,
                      "\n%sNbr [%s] Link DB is empty, triggering "
                      "nbr delete", an_nd_event, nbr->udi.data);
         an_nbr_remove_and_free_nbr(nbr);
     }
}

void
an_nd_nbr_link_cleanup_event_handler (void *link_info_ptr)
{
    an_nbr_t *nbr = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    an_nbr_link_context_t *nbr_link_ctx = NULL;

    if (!link_info_ptr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr link info is NULL, Cant handle acp link removal event",
                 an_bs_event);
        return;
    }

    nbr_link_ctx = (an_nbr_link_context_t *)link_info_ptr;
    if (nbr_link_ctx == NULL)
    {
       DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sContext is NULL", an_nd_event);
       return;
    }

    nbr = nbr_link_ctx->nbr;
    nbr_link_data = nbr_link_ctx->nbr_link_data;

    if (!nbr_link_data || !nbr)
    {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                     "\n%sNull Input Nbr Link data", an_nd_event);
        return;
    }

    an_nbr_remove_nbr_link(nbr, nbr_link_data);

    an_nd_remove_and_free_nbr(nbr); 
}

void
an_nd_nbr_link_cleanup_timer_expired_event_handler (void *link_info_ptr)
{
    an_nbr_link_context_t *nbr_link_ctx = NULL;

    if (!link_info_ptr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr link info is NULL, Cant handle acp link removal event",
                 an_bs_event);
        return;
    }

    nbr_link_ctx = (an_nbr_link_context_t *)link_info_ptr;
    an_acp_nbr_link_cleanup(nbr_link_ctx);
    an_nd_nbr_link_cleanup_event_handler(nbr_link_ctx);
    //free the context - allocated when per link cleanup timer was init
    an_free_guard(nbr_link_ctx);
}

void
an_nd_if_autonomic_init_event_handler (void *if_info_ptr)
{
    an_if_info_t *an_if_info = NULL;
    an_if_t *ifhndl_info, ifhndl;

    if(!if_info_ptr) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle interface autonomic init"
                    " event ");
        return;
    }
    ifhndl_info = (an_if_t *)if_info_ptr;
    ifhndl = *ifhndl_info;

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
       return;
    }
    an_nd_startorstop(ifhndl);
}

void
an_nd_if_autonomic_uninit_event_handler (void *if_info_ptr)
{
    an_if_info_t *an_if_info = NULL;
    an_if_t *ifhndl_info, ifhndl;

    if(!if_info_ptr) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle interface autonomic uninit" 
                    " event ");
        return;
    }
    ifhndl_info = (an_if_t *)if_info_ptr;
    ifhndl = *ifhndl_info;

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
       return;
    }
    an_nbr_db_walk(an_nbr_walk_link_lost_cb, &ifhndl);
}

void
an_nd_device_bootstrap_event_handler (void *info_ptr)
{
    an_nbr_refresh_hello();
}

void
an_nd_sudi_available_event_handler (void *info_ptr)
{
    /* uninit ND first, so that any ND using sUDI is removed */
    if (an_is_global_cfg_autonomic_enabled()) {
        an_nd_uninit();
        an_nd_init();
    }
}

void
an_nd_udi_available_event_handler (void *info_ptr)
{
    an_udi_t my_udi = {};

    if (!an_get_udi(&my_udi)) {
        return;
    }
    /* uninit ND first, so that any ND using sUDI is removed */
    if (an_is_global_cfg_autonomic_enabled()) {
        an_nd_uninit();
        an_nd_init();
    }
}

/*---------------AN ND register for event handlers -------------------------*/
void
an_nd_register_for_events (void) 
{
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_INTERFACE_UP, an_nd_interface_up_event_handler);
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_INTERFACE_DOWN,
                        an_nd_interface_down_event_handler);
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_INTERFACE_ACTIVATE, 
                        an_nd_interface_activate_event_handler);
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_INTERFACE_DEACTIVATE, 
                        an_nd_interface_deactivate_event_handler);
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_TIMER_HELLO_REFRESH_EXPIRED, 
                        an_nd_hello_refresh_timer_expired_event_handler);
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_NBR_ADD, an_nd_nbr_add_event_handler);
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_TIMER_NBR_LINK_CLEANUP_EXPIRED, 
                        an_nd_nbr_link_cleanup_timer_expired_event_handler);
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_INTF_AUTONOMIC_ENABLE, 
                        an_nd_if_autonomic_init_event_handler);
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_INTF_AUTONOMIC_DISABLE, 
                        an_nd_if_autonomic_uninit_event_handler);
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_DEVICE_BOOTSTRAP, 
                        an_nd_device_bootstrap_event_handler);
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_SUDI_AVAILABLE, 
                        an_nd_sudi_available_event_handler);
    an_event_register_consumer(AN_MODULE_ND,
                        AN_EVENT_UDI_AVAILABLE, 
                        an_nd_udi_available_event_handler);
}

