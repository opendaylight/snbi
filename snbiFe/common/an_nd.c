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
#include "../al/an_tunnel.h"
#include "../al/an_list.h"

static an_cerrno an_nbr_link_lost_cb(an_list_t *list,
        const an_list_element_t *current,
        an_list_element_t *next, void *context);

an_timer an_nd_hello_timer;
uint16_t an_nd_if_count = 0;
an_nd_client_t an_nd_global_client_db[AN_ND_CLIENT_MAX] = {
                        {AN_ND_CLIENT_CLI, AN_ND_CFG_DEFAULT},
                        {AN_ND_CLIENT_CONNECT, AN_ND_CFG_DEFAULT},
                        {AN_ND_CLIENT_INTERFACE_TYPE, AN_ND_CFG_DEFAULT}};

an_nd_oper_e an_nd_global_oper = AN_ND_OPER_DOWN;
an_nd_config_state_e an_nd_global_state = AN_ND_CFG_DEFAULT;
extern an_avl_tree an_nbr_tree;
an_avl_compare_e an_nbr_compare(an_avl_node_t *node1, an_avl_node_t *node2);

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

    if (an_if_is_layer2(ifhndl)) {
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

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sDisabling Nbr Discovery on an interface %s", an_nd_event, 
                 an_if_get_name(ifhndl));

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
        return (FALSE);
    }
    if (an_if_is_layer2(ifhndl)) {
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
        an_ipv6_disable_on_interface(ifhndl);
    }
    
    an_if_info->nd_oper = AN_ND_OPER_DOWN;

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
        an_event_interface_activated(ifhndl);
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
    an_avl_uninit(&an_nbr_tree);

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

    if (!an_if_info) {
        return (FALSE);
    }

    v6addr = an_ipv6_get_ll(an_if_info->ifhndl);    
    if (!an_memcmp(&v6addr, (void *)&AN_V6ADDR_ZERO, sizeof(an_v6addr_t))) {
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

    if (!an_if_info) {
        return (FALSE);
    }

    v6addr = an_ipv6_get_ll(an_if_info->ifhndl);    
    if (!an_memcmp(&v6addr, (void *)&AN_V6ADDR_ZERO, sizeof(an_v6addr_t))) {
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

an_walk_e
an_nd_trigger_hello_cb (an_avl_node_t *node, void *data)
{
    an_if_info_t *an_if_info = NULL;

    if (!node) {
        return (AN_WALK_FAIL);
    }
    an_if_info = (an_if_info_t *)node;

    an_nd_trigger_hello_on_if(an_if_info);

    an_thread_check_and_suspend();
    return (AN_WALK_SUCCESS);
}

void
an_nbr_refresh_hello ()
{

    if (!an_nd_is_operating(0)) {
        return;
    }

    an_if_info_db_walk(an_nd_trigger_hello_cb, NULL);
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
        return (NULL);
    }

    nbr->iptable = message->iptable; 

    nbr->udi = message->udi;
    message->udi = empty_udi;

    nbr->device_id = message->device_id; 
    message->device_id = NULL;

    nbr->domain_id = message->domain_id;
    message->domain_id = NULL; 
    
        return (nbr);
}

/* return TRUE if params changed */
an_msg_interest_e
an_nbr_check_params (an_msg_package *message, an_nbr_t *nbr,
                     an_if_t local_ifhndl)
{
    an_msg_interest_e changed = 0;
    an_nbr_link_spec_t *link_data = NULL;

    if (!message || !nbr) {
        return (FALSE);
    }

    if ((an_strlen(message->device_id) != an_strlen(nbr->device_id)) ||
        (an_memcmp(message->device_id, nbr->device_id,
                   an_strlen(nbr->device_id)))) {
        AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_ID);
    }

    if ((an_strlen(message->domain_id) != an_strlen(nbr->domain_id)) ||
        (an_memcmp(message->domain_id, nbr->domain_id,
                   an_strlen(nbr->domain_id)))) {
        AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DOMAIN_ID);
    }

    if (!nbr->an_nbr_link_list) { 
        /* something is wrong, should not reach here */
        return(changed);
    }
/*
    an_log(AN_LOG_NBR_LINK, "\n%sNBR_FOUND List Recvd on Local_ifhndl %s "
                                       "msg->if_name %s"
                                       "msg->ifaddr %s," 
                                       "msg->local_ifhndl %s"
                                       "msg->ipaddr %s",
                                       an_nbr_link_prefix,
                                       an_if_get_name(local_ifhndl),
                                       message->if_name,
                                       an_addr_get_string(&message->if_ipaddr),
                                       an_if_get_name(message->ifhndl),
                                       an_addr_get_string(&message->if_ipaddr));
*/     
     link_data = an_nbr_link_db_search(nbr->an_nbr_link_list,
                                         local_ifhndl,
                                         message->if_ipaddr);
     
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

boolean
an_nbr_update_params (an_msg_package *message,
                      an_nbr_t *nbr,
                      an_if_t local_ifhndl,
                      an_msg_interest_e new_nbr_link_flag)
{
    an_msg_interest_e changed = 0;

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

    if (message->device_id && 
        ((an_strlen(message->device_id) != an_strlen(nbr->device_id)) ||
         (an_memcmp(message->device_id, nbr->device_id, an_strlen(nbr->device_id))))) {

        AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_ID);

        if (nbr->device_id) {
            an_free_guard(nbr->device_id);
            nbr->device_id = NULL;
        }
        if (message->device_id && an_strlen(message->device_id)) {
            nbr->device_id = (uint8_t *)an_malloc_guard(
                           an_strlen(message->device_id), "AN MSG device id");
            if (!nbr->device_id) {
                return (FALSE);
            }
            an_memcpy_guard(nbr->device_id, message->device_id, 
                           an_strlen(message->device_id));
        }
    }

    if (message->domain_id && 
        ((an_strlen(message->domain_id) != an_strlen(nbr->domain_id)) ||
         (an_memcmp(message->domain_id, nbr->domain_id, an_strlen(nbr->domain_id))))) {

        AN_SET_BIT_FLAGS(changed, AN_MSG_INT_DOMAIN_ID);

        if (nbr->domain_id) {
            an_free_guard(nbr->domain_id);
            nbr->domain_id = NULL;
        }
        if (message->domain_id && an_strlen(message->domain_id)) {
            nbr->domain_id = (uint8_t *)an_malloc_guard(
                             an_strlen(message->domain_id), "AN MSG domain id");
            if (!nbr->domain_id) {
                return (FALSE);
            }
            an_memcpy_guard(nbr->domain_id, message->domain_id, 
                             an_strlen(message->domain_id));
        }
    }

    if (AN_CHECK_BIT_FLAGS(new_nbr_link_flag, AN_MSG_INT_NEW_NBR_LINK)) {
        an_nbr_update_link_to_nbr(message, nbr, local_ifhndl);
    }

    if (changed) {
        an_event_nbr_params_changed(nbr, changed);
    } 

    an_event_nbr_refreshed(nbr);

    return (changed);
}

void
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
       return;
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
       return;
    }
    an_nbr_link_init_cleanup_timer(nbr, nbr_link_data);
    nbr->num_of_links = nbr->num_of_links + 1;

    an_event_nbr_link_add(nbr, nbr_link_data);
}

boolean
an_nd_incoming_hello (an_msg_package *message, an_pak_t *pak,  
                      an_if_t local_ifhndl)
{
    an_nbr_t *nbr = NULL;
    boolean res = FALSE;
    an_msg_interest_e changed = 0;
    an_nbr_link_spec_t *nbr_link_data = NULL;

    if (!pak || !message || !local_ifhndl) {
        return (FALSE);
    }

    if (!message->udi.data || !message->udi.len) {
        return (FALSE);
    }

    if (!an_nd_is_operating(message->ifhndl)) {
        return (FALSE);
    }

    nbr = an_nbr_db_search(message->udi);
    if (nbr) {
        changed = an_nbr_check_params(message, nbr, local_ifhndl);

        if (changed) {
           an_nbr_update_params(message, nbr, local_ifhndl, changed);

        } else {
            DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                         "\n%sNeighbor [%s] entry already exists in Nbr DB, "
                         "refreshing the Nbr in Nbr DB", 
                         an_nd_db, nbr->udi.data);    
            an_event_nbr_refreshed(nbr);
        }

    } else {
         /*
         * Create a New Neighbor
         */
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNbr[%s] not found in Nbr DB, hence creating new nbr",
                     an_nd_db, message->udi.data)
        nbr = an_nd_convert_message_to_nbr(message);
        
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
                return (FALSE);
            }            
            an_nbr_link_init_cleanup_timer(nbr, nbr_link_data);
            nbr->num_of_links = nbr->num_of_links + 1;
        
        } else {
            DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                         "%sNbr [%s] Link DB creation failed, "
                         "not able to add the nbr to Nbr DB", an_nd_db, 
                         nbr->udi.data);
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
an_nd_get_hello (an_if_t ifhndl)
{
    an_msg_package *message = NULL;
    an_v6addr_t v6addr = AN_V6ADDR_ZERO; 
    an_udi_t udi = {};
    uint8_t *if_name = NULL;
    an_cert_t domain_device_cert = {};
    
    message = an_msg_mgr_get_empty_message_package();    

    an_msg_mgr_init_header(message, AN_PROTO_ADJACENCY_DISCOVERY, 
                           AN_ADJACENCY_DISCOVERY_HELLO);

    message->ifhndl = ifhndl;
    an_addr_set_from_v6addr(&message->src, an_ipv6_get_ll(message->ifhndl)); 
    message->dest = an_ll_scope_all_node_mcast;

    an_get_udi(&udi);
    if (!udi.data || !udi.len) {
        return (NULL);
    }
 
    if (udi.len) {
        message->udi.data = (uint8_t *)an_malloc_guard(udi.len, "AN MSG UDI");
        if (!message->udi.data) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        }
        message->udi.len = udi.len;
        an_memcpy_guard(message->udi.data, udi.data, udi.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);
    }

    if (an_get_domain_cert(&domain_device_cert)) {
        message->device_id = (uint8_t *)an_malloc_guard(
                1+an_strlen(an_get_device_id()), "AN MSG Device ID");
        if (!message->device_id) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        }
        an_memcpy_guard(message->device_id, an_get_device_id(), 
                1+an_strlen(an_get_device_id()));
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DEVICE_ID);

        message->domain_id = (uint8_t *)an_malloc_guard(
                1+an_strlen(an_get_domain_id()), "AN MSG Domain ID");
        if (!message->domain_id) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        }
        an_memcpy_guard(message->domain_id, an_get_domain_id(), 
                1+an_strlen(an_get_domain_id()));
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DOMAIN_ID);
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
    an_memcpy_guard(message->if_name, if_name, 1+an_strlen(if_name));
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_IF_NAME);

    return(message);
}

void
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
        return;
    }

    link_ctx->nbr = nbr;
    link_ctx->nbr_link_data = nbr_link_data;

    DEBUG_AN_LOG(AN_LOG_ND_EVENT,  AN_DEBUG_MODERATE, NULL, 
                 "\n%s Nbr Link Cleanup Initiated", an_nd_event);
    an_timer_init(&nbr_link_data->cleanup_timer,
                  AN_TIMER_TYPE_PER_NBR_LINK_CLEANUP, link_ctx, FALSE);
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

    if_data = (an_nbr_link_context_t *) context;

    if (current == NULL || if_data == NULL)    {
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }
    
    curr_data = (an_nbr_link_spec_t *) current->data;
    
    if (if_data->nbr_link_data->local_ifhndl == curr_data->local_ifhndl) {
          an_event_nbr_link_lost(if_data->nbr, curr_data);
          an_event_remove_and_free_nbr(if_data->nbr);
    }
  
   return (AN_CERR_SUCCESS);
}

an_walk_e
an_nbr_walk_link_lost_cb (an_avl_node_t *node, void *args)
{
   an_nbr_t *nbr = (an_nbr_t *)node;
   an_if_t *ifhndl = (an_if_t *)args;
   an_nbr_link_spec_t nbr_link_data;
   an_nbr_link_context_t nbr_link;
   an_cerrno ret;
   
   if (!nbr || !args) {
      return (AN_WALK_FAIL);
   }
   
   nbr_link_data.local_ifhndl = *ifhndl;
   nbr_link.nbr_link_data = &nbr_link_data;
   nbr_link.nbr = nbr;
   ret = an_nbr_link_db_walk(nbr->an_nbr_link_list, an_nbr_link_lost_cb, 
                             &nbr_link);
   
   return (AN_WALK_SUCCESS);
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
