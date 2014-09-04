/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an.h"
#include "an_ni.h"
#include "an_acp.h"
#include "an_msg_mgr.h"
#include "an_if_mgr.h"
#include "../al/an_if.h"
#include "../al/an_addr.h"
#include "../al/an_ipv6.h"
#include "../al/an_avl.h"
#include "../al/an_mem.h"
#include "../al/an_logger.h"
#include "../al/an_tunnel.h"
#include "../al/an_misc.h"
#include "../al/an_ipv6_send.h"
#include "../al/an_sudi.h"
#include "../al/an_str.h"
#include "../al/an_routing.h"
#include "../al/an_ntp.h"
#include "an_nbr_db.h"
#include "an_nd.h"
#include "an_event_mgr.h"
//#include "an_topo_disc.h"
#include "an_cnp.h"
#include "../al/an_ipsec.h"
#include "../al/an_ike.h"

#define AN_ACP_TUNN_MODE_GRE_IPV6 21
#define AN_LOOPBACK_NUM_START 100000
#define AN_LOOPBACK_NUM_END 2147483647

uint16_t an_routing_ospf = 0;
an_if_t an_source_if;


uint32_t an_loopback_id = AN_LOOPBACK_NUM_START;

static void an_acp_connect_state_set(an_if_t ifhndl,
                an_acp_ext_conn_e ext_conn_state);

boolean an_acp_initialized = FALSE;
uint8_t an_acp_channel_supported = AN_ACP_CHANNEL_PHYSICAL | AN_ACP_CHANNEL_GRE_IPV6;
uint8_t an_acp_security_supported = AN_ACP_SEC_NONE;

/***************************************************************/
/* Global Strucure to set the ACP channel and security cap sets */
typedef struct an_acp_cap_set_ {
    uint16_t length;
    uint16_t member_length;
    uint8_t *value;
} an_acp_cap_set_t;

an_acp_cap_set_t an_acp_channel_cap_set;
an_acp_cap_set_t an_acp_security_cap_set;

boolean an_set_channel_cli = FALSE;
boolean an_set_security_cli = FALSE;

/****************************************************************/

const uint8_t *
an_acp_cnp_get_param_str (an_acp_cnp_param_e param_id) 
{
    switch(param_id) {
        case AN_ACP_CNP_PARAM_CHANNEL:
            return "AN_ACP_CNP_PARAM_CHANNEL";
        case AN_ACP_CNP_PARAM_SECURE:
            return "AN_ACP_CNP_PARAM_SECURE";
        default:
            break;
    }
    return "AN_ACP_CNP_PARAM_NONE";
}

uint8_t *
an_acp_get_value_string (an_cnp_capability_set_t *capability_set) 
{
    switch (capability_set->param_id) {
    case AN_ACP_CNP_PARAM_CHANNEL:
        if (capability_set->u.vector.value[0] == AN_ACP_CHANNEL_GRE_IPV6) {
            return ("GRE Tunnel");
        }
    break;
    case AN_ACP_CNP_PARAM_SECURE:
        if (capability_set->u.vector.value[0] == AN_ACP_SEC_IPSEC) {
            return ("IPSEC");
        } 
    break;
    default:
    break;
    }
    return ("Unknown");
}
    
/**************** ACP Client DB *************************/

an_avl_tree an_acp_client_tree;
static an_acp_client_t *an_acp_client_database = NULL;
static an_mem_chunkpool_t *an_acp_client_pool = NULL;
static const uint16_t AN_ACP_CLIENT_POOL_SIZE = 64;

static an_acp_client_t *
an_acp_client_alloc (void)
{
    an_acp_client_t *client = NULL;

    if (!an_acp_client_pool) {
        /* Allocate AN client chunk pool */
        an_acp_client_pool = an_mem_chunkpool_create(sizeof(an_acp_client_t),
                             AN_ACP_CLIENT_POOL_SIZE, 
                             "AN ACP Client ChunkPool");
    }

    /* Allocate a AN client */
    client = an_mem_chunk_malloc(an_acp_client_pool);
    if (!client) {
        if (an_mem_chunkpool_destroyable(an_acp_client_pool)) {
            an_mem_chunkpool_destroy(an_acp_client_pool);
            an_acp_client_pool = NULL;
        }
        return (NULL);
    }

    return (client);
}

static void
an_acp_client_free (an_acp_client_t *client)
{
    if (!client) {
        return;
    }

    an_mem_chunk_free(&an_acp_client_pool, client);
}

static an_avl_compare_e
an_acp_client_compare (an_avl_node_t *node1, an_avl_node_t *node2)
{
    an_acp_client_t *client1 = (an_acp_client_t *)node1;
    an_acp_client_t *client2 = (an_acp_client_t *)node2;

    if (!client1 && !client2) {
        return (AN_AVL_COMPARE_EQ);
    } else if (!client1) {
        return (AN_AVL_COMPARE_LT);
    } else if (!client2) {
        return (AN_AVL_COMPARE_GT);
    }

    if (client1->id < client2->id) {
        return (AN_AVL_COMPARE_LT);
    } else if (client1->id > client2->id) {
        return (AN_AVL_COMPARE_GT);
    } else { 
        return (AN_AVL_COMPARE_EQ);
    }
}

static boolean
an_acp_client_db_insert (an_acp_client_t *client)
{
    if (!client) {
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sInserting Client %d into ACP Client DB",  
                 an_bs_event, client->id);
    an_avl_insert_node((an_avl_top_p *)&an_acp_client_database,
                  (an_avl_node_t *)client, an_acp_client_compare,
                  &an_acp_client_tree); 

    return (TRUE);
}

static boolean
an_acp_client_db_remove (an_acp_client_t *client)
{
    if (!client) {
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sRemoving Client %d from ACP Client DB", 
                 an_bs_event, client->id);
    an_avl_remove_node((an_avl_top_p *)&an_acp_client_database,
                  (an_avl_node_t *)client, an_acp_client_compare,
                  &an_acp_client_tree); 

    return (TRUE);
}

static an_acp_client_t *
an_acp_client_db_search (an_acp_client_id_t client_id)
{
    an_acp_client_t goal_client = {};
    an_acp_client_t *client = NULL;
    
    an_avl_node_t *avl_type  = (an_avl_node_t *)&goal_client;
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sSearching ACP Client %d in Client DB", 
                 an_bs_event, client_id);
    goal_client.id = client_id;
    client = (an_acp_client_t *)
          an_avl_search_node((an_avl_top_p)an_acp_client_database,
                             avl_type, an_acp_client_compare, 
                             &an_acp_client_tree); 

    return (client);
}

void
an_acp_client_db_walk (an_avl_walk_f walk_func, void *args)
{
    an_avl_walk_all_nodes((an_avl_top_p *)&an_acp_client_database, walk_func, 
                          an_acp_client_compare, args, &an_acp_client_tree);   
}

static an_walk_e
an_acp_client_db_init_cb (an_avl_node_t *node, void *args)
{
    an_acp_client_t *client = (an_acp_client_t *)node;

    if (!client) {
        return (AN_WALK_FAIL);
    }

    an_acp_client_db_remove(client);
    an_acp_client_free(client);

    return (AN_WALK_SUCCESS);
}

void
an_acp_client_db_init (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sInitializing ACP Client DB", an_bs_event);
    an_acp_client_db_walk(an_acp_client_db_init_cb, NULL);
}

/***************** ACP Client Interaction *******************/

an_acp_client_status_e
an_acp_client_register (an_acp_client_t *client_info)
{
    an_acp_client_t *client = NULL;

    if (!client_info || !client_info->id || !client_info->callback) {
        return (AN_ACP_CLIENT_INVALID_ARGS);
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sRequest to register ACP client "
                 "(%d, %u, %u, %20s)", an_bs_event,
                 client_info->id, client_info->handle, 
                 client_info->callback, client_info->description);

    client = an_acp_client_db_search(client_info->id);
    if (client) {
        if (client->callback != client_info->callback) {
            return (AN_ACP_CLIENT_ALREADY_REGD);
        }
        client_info->handle = (an_acp_client_handle)client;
        return (AN_ACP_CLIENT_SUCCESS);
    }

    client = an_acp_client_alloc();
    if (!client) {
        return (AN_ACP_CLIENT_MEM_FAILURE);
    }

    client->id = client_info->id;
    client->callback = client_info->callback;
    client->handle = (an_acp_client_handle)client;
    an_snprintf(client->description, AN_ACP_CLIENT_DESCRIPTION_MAX, 
             "%s", client_info->description);
    
    an_acp_client_db_insert(client);

    client_info->handle = client->handle;

    /* Do any other initiation required for this client */

    return (AN_ACP_CLIENT_SUCCESS);
}

an_acp_client_status_e
an_acp_client_unregister (an_acp_client_t *client_info)
{
    an_acp_client_t *client = NULL;

    if (!client_info || !client_info->id || 
        !client_info->handle) {
        return (AN_ACP_CLIENT_INVALID_ARGS);
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sRequest to unregister ACP client "
                 "(%d, %u, %u, %20s)", an_bs_event,
                 client_info->id, client_info->handle, 
                 client_info->callback, client_info->description);

    client = an_acp_client_db_search(client_info->id);
    if (!client) {
        return (AN_ACP_CLIENT_NOT_REGD);
    } else { 
        if (client->handle != client_info->handle) {
            return (AN_ACP_CLIENT_HANDLE_MISMATCH);
        }
    }

    an_acp_client_db_remove(client);
    an_acp_client_free(client);
    return (AN_ACP_CLIENT_SUCCESS);
}

an_acp_client_status_e
an_acp_client_send_data (an_acp_client_comm_t *client_comm)
{
    an_acp_client_t *client_info = NULL;
    an_acp_client_t *client = NULL;
    an_msg_package *message = NULL;

    if (!client_comm || an_addr_is_zero(client_comm->dest_addr) ||
        !client_comm->payload.len || !client_comm->payload.data) {
        return (AN_ACP_CLIENT_INVALID_ARGS); 
    }

    client_info = &client_comm->client_info;
    if (!client_info || !client_info->id || 
        !client_info->handle) {
        return (AN_ACP_CLIENT_INVALID_ARGS);
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sRequest to send data of length %d "
                 "from client %d", an_bs_event,
                 client_comm->payload.len, client_info->id);
      
    client = an_acp_client_db_search(client_info->id);
    if (!client) {
        return (AN_ACP_CLIENT_NOT_REGD);
    } else {
        if (client->handle != client_info->handle) {
            return (AN_ACP_CLIENT_HANDLE_MISMATCH);
        }
    }
       
    message = an_msg_mgr_get_empty_message_package();
    message->dest = client_comm->dest_addr;
    message->src = client_comm->source_addr; 
    message->iptable = an_get_iptable();
    message->ifhndl = client_comm->ifhndl;

    an_msg_mgr_init_header(message, AN_PROTO_ACP, 
                           AN_MSG_ACP_DATA);
    message->header.reserved = client_info->id;

    message->payload.len = client_comm->payload.len;
    message->payload.data = 
            (uint8_t *)an_malloc_guard(client_comm->payload.len, 
                                       "AN Msg payload");
    if (!message->payload.data) {
        return (AN_ACP_CLIENT_MEM_FAILURE);
    }
    an_memcpy_guard(message->payload.data, client_comm->payload.data, 
           client_comm->payload.len); 
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_ACP_PAYLOAD);

    an_msg_mgr_send_message(message);

    return (AN_ACP_CLIENT_SUCCESS);
}

void
an_acp_incoming_message (an_msg_package *acp_message)
{
    an_acp_client_id_t id = 0;
    an_acp_client_comm_t client_comm = {};
    an_acp_client_t *client = NULL;

    if (!acp_message) {
        return;
    }

    id = acp_message->header.reserved;
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sIncoming ACP message from client %d", an_bs_event, id);

    client = an_acp_client_db_search(id);
    if (client) {
        client_comm.client_info.id = id;
        client_comm.dest_addr = acp_message->dest;
        client_comm.source_addr = acp_message->src;
        client_comm.ifhndl = acp_message->ifhndl;
        client_comm.payload = acp_message->payload;

        client->callback(&client_comm);
    } else {
        /* Client not yet registered, drop the message */
    }

    an_msg_mgr_free_message_package(acp_message); 
}

/******************* ACP Setup Section ***********************/

boolean
an_acp_routing_enable_on_required_interface_cb (an_if_t ifhndl, void *args)
{
    an_routing_cfg_t *routing_info = (an_routing_cfg_t *)args;
    an_if_info_t *an_if_info = NULL;

    if (!ifhndl || !an_if_is_up(ifhndl) || !routing_info) {
        return FALSE;
    }

    an_if_info = an_if_info_db_search(ifhndl, FALSE);

    if (an_if_check_routing_required(an_if_info)) {
        an_acp_routing_enable_on_interface(ifhndl, *routing_info);
        return TRUE;
    }
    else {
        return FALSE;
    }
}

void
an_acp_routing_enable_on_required_interfaces (an_routing_cfg_t *routing_info)
{
    an_if_walk(an_acp_routing_enable_on_required_interface_cb, (void *)routing_info);
}

static an_addr_t prev_anra_ip; 

void
an_acp_routing_track_anra (void)
{
    an_addr_t anra = AN_ADDR_ZERO;

    anra = an_get_anra_ip();
    if (an_addr_equal(&prev_anra_ip, &anra)) {
        return;
    } 

    if (!an_addr_is_zero(prev_anra_ip)) {
        an_rwatch_stop_track_ipaddr();
    }

    if (!an_addr_is_zero(anra)) {
        an_rwatch_start_track_ipaddr(anra, an_get_afi(), an_get_iptable());
    }

    prev_anra_ip = anra;

}

static boolean
an_config_loopback_cb (an_if_t ifhndl)
{
    an_addr_t addr = AN_ADDR_ZERO;
    an_routing_cfg_t routing_info = {};
 
    if (!an_if_is_up(ifhndl)) {
        return (TRUE);
    }

    if (an_if_is_loopback(ifhndl)) {

        /* Disable AN ND in ACP */

        an_nd_set_preference(ifhndl, AN_ND_CLIENT_INTERFACE_TYPE, AN_ND_CFG_DISABLED);
        an_nd_startorstop(ifhndl);

        an_if_make_volatile(ifhndl);

        addr = an_get_device_ip();
        an_ipv6_configure_addr_on_interface(ifhndl, addr, 128);

        routing_info = an_get_routing_info(); 
        an_acp_routing_enable_on_interface(ifhndl, routing_info);
        an_source_if = ifhndl;
        return (FALSE);
    }
    return (TRUE);
}

static void
an_config_loopback (void)
{
    an_if_t loopback_ifhndl = 0;
    an_if_info_t *if_info = NULL;

    while (TRUE) {

        if (an_if_check_loopback_exists(an_loopback_id)) {
            an_loopback_id++;
        } else {
            break;
        }
        if (an_loopback_id == AN_LOOPBACK_NUM_END) {
            an_loopback_id = AN_LOOPBACK_NUM_START;
        }
        an_thread_check_and_suspend();
    }
    loopback_ifhndl = an_if_create_loopback(an_loopback_id);
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sConfigured Loopback Interface [%d]", an_bs_event, an_loopback_id);

    if (loopback_ifhndl) {
        an_config_loopback_cb(loopback_ifhndl);
    }

}

static void
an_unconfig_loopback (void)
{
    an_if_t lb_ifhndl = 0;
    an_if_info_t *if_info = NULL;

    lb_ifhndl = an_get_autonomic_loopback_ifhndl();

    if_info = an_if_info_db_search(lb_ifhndl, FALSE);
    if (if_info) {
        if_info->autonomically_created = FALSE;
        an_if_remove_loopback(lb_ifhndl);
        an_if_info_db_remove(if_info);
        an_if_info_free(if_info);
    }
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sUnconfigured Loopback %d", an_bs_event, an_loopback_id);
}

an_if_t
an_tunnel_create_and_configure (an_addr_t src_ip, an_addr_t dst_ip, 
                                an_if_t src_if)
{
    uint8_t tunn_mode = AN_ACP_TUNN_MODE_GRE_IPV6;
    an_if_t tunn_ifhndl = 0;
    an_routing_cfg_t routing_info;
    
    an_memset(&routing_info, 0, sizeof(routing_info));
    tunn_ifhndl = an_tunnel_create(&src_ip, &dst_ip, src_if, tunn_mode);
    if (!tunn_ifhndl) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sFailed to create tunnel for "
                     "AN Control Plane channel", an_bs_event);
        return (0);
    }

    
    if (!an_ipv6_enable_on_interface(tunn_ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sFailed to enable IPV6 on AN control plane tunnel",
                     an_bs_event);
        an_tunnel_remove(tunn_ifhndl);
        return (0);
    }

    routing_info = an_get_routing_info(); 
    an_acp_routing_enable_on_interface(tunn_ifhndl, routing_info);
    
    //an_if_make_volatile(tunn_ifhndl);
    return (tunn_ifhndl);
}

boolean 
an_acp_remove_ipsec_per_nbr_link (an_nbr_t *nbr, 
                                  an_nbr_link_spec_t *nbr_link_data)
{

    an_idbtype *tunnel_idb = NULL;

    if (!nbr || !nbr_link_data) {
        return (FALSE);
    }

    if (AN_ACP_SEC_NONE == nbr_link_data->acp_info.sec_type) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sChannel Security not yet established to nbr", 
                     an_bs_event);    
        return (TRUE);
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sRemoving ACP IPsec per nbr link with the nbr tunnel "
                 "state %d, channel type %d", an_bs_event, 
                 nbr_link_data->acp_info.channel_spec.tunn_info.state,
                 nbr_link_data->acp_info.channel_type);
    tunnel_idb = an_if_number_to_swidb(
                    nbr_link_data->acp_info.channel_spec.tunn_info.ifhndl);

    if (tunnel_idb) {
        an_ipsec_remove_on_tunnel(tunnel_idb);
    }else {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sTunnel idb Null, cant remove IPSec profile", 
                     an_bs_event);
    }
    nbr_link_data->acp_info.sec_type = AN_ACP_SEC_NONE;
    an_syslog(AN_SYSLOG_ACP_IPSEC_TO_NBR_REMOVED,
                    an_if_get_name(
                    nbr_link_data->acp_info.channel_spec.tunn_info.ifhndl),
                    nbr->udi.data,
                    nbr_link_data->acp_info.channel_spec.tunn_info.state);
    return (TRUE);
}

an_if_t
an_acp_get_acp_info_per_nbr_link (an_nbr_t *nbr, 
                                  an_nbr_link_spec_t *nbr_link_data)
{
    an_if_t acp_if = 0;

    if (!nbr || !nbr_link_data) {
        return (0);
    }

    if (AN_ACP_CHANNEL_NONE == nbr_link_data->acp_info.channel_type) {
        return (0);
    }

    switch (nbr_link_data->acp_info.channel_type) {
    case AN_ACP_CHANNEL_PHYSICAL:
        acp_if = nbr_link_data->acp_info.channel_spec.phy_info.ifhndl;
        break;
    
    case AN_ACP_CHANNEL_GRE_IPV6:
        acp_if = nbr_link_data->acp_info.channel_spec.tunn_info.ifhndl;
        break;

    case AN_ACP_CHANNEL_VLAN:
    default:
        acp_if = 0;
        break;
    }

    return (acp_if);
}

an_if_t
an_acp_create_per_nbr_link (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    an_addr_t addr_src = AN_ADDR_ZERO;
    an_if_t tunn_ifhndl = 0;

    if (!nbr || !nbr_link_data) {
        return (0);
    }

    if (!an_acp_initialized) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sAN Control Plane not initialized, hence failed to "
                     "create AN Control Plane to nbr [%s] on %s", 
                     an_bs_event, nbr->udi.data, 
                     an_if_get_name(nbr_link_data->local_ifhndl)); 
        return (0);
    }

    if (!nbr_link_data->acp_info.channel_negotiated) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNegotiated AN Control Plane channel type with the "
                     "Nbr[%s] is NONE", an_bs_event, nbr->udi.data);
        return (0);
    }
   
    if (nbr_link_data->acp_info.channel_type) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                    "\n%sAN Control Plane channel is already established to Nbr "
                    "[%s] on %s", an_bs_event, nbr->udi.data, 
                    an_if_get_name(nbr_link_data->local_ifhndl));
        return (nbr_link_data->acp_info.channel_spec.tunn_info.ifhndl);
    }

    if (an_ni_is_nbr_inside(nbr)) {

        switch (nbr_link_data->acp_info.channel_negotiated) {
        case AN_ACP_CHANNEL_PHYSICAL:
            an_acp_routing_enable_on_interface(nbr_link_data->local_ifhndl, 
                                               an_get_routing_info());

            nbr_link_data->acp_info.channel_type = 
                                nbr_link_data->acp_info.channel_negotiated;
            nbr_link_data->acp_info.channel_spec.phy_info.ifhndl = 
                                nbr_link_data->local_ifhndl;
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sNegotiated AN Control Plane channel on %s is %s", 
                         an_bs_event, 
                         an_if_get_name(nbr_link_data->local_ifhndl), 
                         "AN_ACP_CHANNEL_PHYSICAL");
            break;

        case AN_ACP_CHANNEL_GRE_IPV6:

            an_addr_set_from_v6addr(&addr_src, 
                                  an_ipv6_get_ll(nbr_link_data->local_ifhndl));
            tunn_ifhndl = an_tunnel_create_and_configure(addr_src, 
                          nbr_link_data->ipaddr, nbr_link_data->local_ifhndl);
            if (tunn_ifhndl) {
                an_nd_set_preference(tunn_ifhndl, AN_ND_CLIENT_INTERFACE_TYPE, 
                            AN_ND_CFG_DISABLED);
                an_nd_startorstop(tunn_ifhndl);

                nbr_link_data->acp_info.channel_type = 
                                    nbr_link_data->acp_info.channel_negotiated;
                nbr_link_data->acp_info.channel_spec.tunn_info.ifhndl = 
                                                     tunn_ifhndl;
                nbr_link_data->acp_info.channel_spec.tunn_info.state = 
                                                     AN_ACP_TUNN_CREATED_UP;
                DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                             "\n%sNegotiated AN Control Plane channel on %s "
                             "is %s", an_bs_event,
                             an_if_get_name(nbr_link_data->local_ifhndl),
                             "AN_ACP_CHANNEL_GRE_IPV6");
            }
            break;
        
        case AN_ACP_CHANNEL_VLAN:
        default:
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sNegotiated AN Control Plane channel to Nbr [%s] "
                          "is of unsupported type", an_bs_event, nbr->udi.data);
            break;
        }

        if (nbr_link_data->acp_info.channel_type && 
            AN_CHECK_BIT_FLAGS(nbr_link_data->acp_info.channel_negotiated, 
                               nbr_link_data->acp_info.channel_type)) {
            an_event_acp_to_nbr_created(nbr);

            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sCreated AN Control Plane channel to nbr [%s] on %s", 
                         an_bs_event, nbr->udi.data, 
                         an_if_get_name(nbr_link_data->local_ifhndl));
            an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_CREATED,
                      an_if_get_name(an_acp_get_acp_info_per_nbr_link(nbr, 
                      nbr_link_data)), nbr->udi.data,
                      an_if_get_name(nbr_link_data->local_ifhndl));
            an_event_acp_negotiate_security_with_nbr_link(nbr, nbr_link_data);
        } else {
            an_memset((uint8_t *)&nbr_link_data->acp_info, 0, 
                      sizeof(nbr_link_data->acp_info));
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sFailed to creat AN Control Plane channel to nbr "
                         "[%s] on %s", an_bs_event, nbr->udi.data, 
                         an_if_get_name(nbr_link_data->local_ifhndl));

            an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_FAILED,
                   nbr->udi.data, an_if_get_name(nbr_link_data->local_ifhndl));
        }
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNbr [%s] not in the AN domain, hence failed to "
                     "create AN Control Plane to Nbr", 
                     an_bs_event, nbr->udi.data);
    }
    return (tunn_ifhndl);
}

void
an_acp_create_ipsec_per_nbr_link (an_nbr_t *nbr, 
                                  an_nbr_link_spec_t *nbr_link_data)
{
    an_idbtype *tunnel_idb = NULL;

    if (!nbr) {
        return;
    }

    if (!an_acp_initialized) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sACP not initialized, hence failed to create" 
                     " ACP Security(IPsec) to nbr [%s]", an_bs_event, 
                     nbr->udi.data); 
        return;
    }

    if (!nbr_link_data->acp_info.channel_type || 
        !an_acp_get_acp_info_per_nbr_link(nbr, nbr_link_data)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, "\n%sACP Channel "
                     "to Nbr[%s] is not yet Created, hence can't create "
                     "ACP Security", an_bs_event, nbr->udi.data);
        return;
    }

    if (nbr_link_data->acp_info.sec_type && 
        AN_CHECK_BIT_FLAGS(nbr_link_data->acp_info.sec_negotiated, 
                           nbr_link_data->acp_info.sec_type)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sACP Security (IPsec) already established to Nbr [%s]",
                     an_bs_event, nbr->udi.data);
        return;
    }

    switch (nbr_link_data->acp_info.sec_negotiated) {
    case AN_ACP_SEC_NONE:
        break;

    case AN_ACP_SEC_IPSEC:
        if (nbr_link_data->acp_info.channel_spec.tunn_info.state == 
                                                      AN_ACP_TUNN_CREATED_UP) {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sACP Tunnel is already UP, creating IPsec"
                         " security of type %s", an_bs_event, "AN_ACP_SEC_IPSEC");
            nbr_link_data->acp_info.sec_spec.ipsec_info.tunnel_mode = TRUE;
            nbr_link_data->acp_info.sec_type = 
                                        nbr_link_data->acp_info.sec_negotiated;
            tunnel_idb = an_if_number_to_swidb(
                    nbr_link_data->acp_info.channel_spec.tunn_info.ifhndl);
            if (tunnel_idb) {
                an_ipsec_apply_on_tunnel(tunnel_idb);
            }else {
                DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                             "\n%sTunnel idb Null, cant apply IPSec profile", 
                             an_bs_event);
            }
    
        } else {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sAN Control Plane not created to nbr [%s], "
                         "since AN Control Plane Tunnel state is not UP", 
                         an_bs_event, nbr->udi.data);
        }
        break;
    
    case AN_ACP_SEC_MACSEC:
    default:
        break;
    
    }
}

void
an_acp_init_acp_info_per_nbr_link (an_nbr_link_spec_t *nbr_link)
{
    if (!nbr_link) {
        return;
    }
    an_memset((uint8_t *)&nbr_link->acp_info, 0, sizeof(nbr_link->acp_info));
}

boolean
an_acp_remove_per_nbr_link (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    an_acp_tunn_info_t tunn_info;
    an_routing_cfg_t routing_info = {};

    if (!nbr || !nbr_link_data) {
        return (FALSE);
    }

    if (!nbr_link_data->acp_info.channel_type) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sAN Control Plane channel not yet established to Nbr "
                     "[%s]", an_bs_event, nbr->udi.data);
        return (TRUE);
    }
    
    tunn_info = nbr_link_data->acp_info.channel_spec.tunn_info;

    if (tunn_info.state == AN_ACP_TUNN_CREATED_UP) {
        routing_info = an_get_routing_info(); 
        an_acp_routing_disable_on_interface(tunn_info.ifhndl, routing_info);
        an_tunnel_remove(tunn_info.ifhndl);
        an_acp_init_acp_info_per_nbr_link(nbr_link_data);

        an_event_acp_to_nbr_removed(nbr);
        
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sAN Control plane channel to Nbr [%s] is removed", 
                     an_bs_event,
                     nbr->udi.data); 
    }

    return (TRUE);
}

void 
an_acp_negotiate_channel_per_nbr_link (an_nbr_t *nbr, 
                                       an_nbr_link_spec_t *nbr_link_data)
{
    an_addr_t addr_src = AN_ADDR_ZERO;
    an_cnp_api_status_e status = 0;

    if (!nbr || !nbr_link_data)
        return;

    an_addr_set_from_v6addr(&addr_src, 
                            an_ipv6_get_ll(nbr_link_data->local_ifhndl));
    
    status = an_cnp_negotiate(AN_CNP_FEAT_ID_ACP, AN_ACP_CNP_PARAM_CHANNEL,
                              nbr_link_data->ipaddr, addr_src, an_get_iptable(), 
                              nbr_link_data->local_ifhndl);
         
    if (status != AN_CNP_API_STATUS_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL, 
                     "\n%sAN control plane negotiation for feature[%s] and " 
                     "parameter[%s] with \n%41snbr[%s] on interface %s addressed "
                     "%s \n%41sreturned status %s", an_bs_event,
                     "AN_CNP_FEAT_ID_ACP", "AN_ACP_CNP_PARAM_CHANNEL", 
                     nbr->udi.data, an_addr_get_string(&nbr_link_data->ipaddr), " ",  
                     an_if_get_name(nbr_link_data->local_ifhndl), " ",
                     an_cnp_get_api_status_names(status));
        return;
    }
   
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL, 
                 "\n%sAN control plane negotiation for feature[%s] and " 
                 "parameter[%s] with \n%41snbr[%s] on interface %s addressed %s"
                 "\n%41sreturned status %s", an_bs_event,
                 "AN_CNP_FEAT_ID_ACP", "AN_ACP_CNP_PARAM_CHANNEL", 
                 nbr->udi.data, an_addr_get_string(&nbr_link_data->ipaddr), " ",  
                 an_if_get_name(nbr_link_data->local_ifhndl), " ",
                 an_cnp_get_api_status_names(status));
    return;
}

boolean
an_acp_create_to_nbr_for_all_valid_nbr_links (an_nbr_t *nbr)
{
    an_list_element_t *elem = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    int i = 0;
            
    AN_FOR_ALL_DATA_IN_LIST(nbr->an_nbr_link_list, elem, nbr_link_data) {
        if (nbr_link_data != NULL) {
            i++;
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sCreate AN Control Plane for all the nbr[%s] "
                         "links of count [%d]", an_bs_event, nbr->udi.data, i);
            an_acp_negotiate_channel_per_nbr_link(nbr, nbr_link_data);
        }
    }
   
    return TRUE;
}

static an_walk_e 
an_acp_create_nbrs_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    
    if (!nbr) {
        return (AN_WALK_FAIL);
    }
   
    an_acp_create_to_nbr_for_all_valid_nbr_links(nbr);
    return (AN_WALK_SUCCESS);
}

static void 
an_acp_create_for_all_valid_neighbors (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sCreating AN Control Plane for all bootstrapped nbrs, "
                 "walking the Nbr DB", an_bs_event);
    
    an_nbr_db_walk(an_acp_create_nbrs_cb, NULL);
}

boolean 
an_acp_remove_to_nbr_for_all_valid_nbr_links (an_nbr_t *nbr)
{
    an_list_element_t *elem = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    int i = 0;

    AN_FOR_ALL_DATA_IN_LIST(nbr->an_nbr_link_list, elem, nbr_link_data) {
        if (nbr_link_data != NULL) {
            i++;
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sRemove AN Control Plane for all valid Nbr[%s] "
                         "links of interface count [%d]", 
                         an_bs_event, nbr->udi.data, i);
            an_acp_remove_per_nbr_link(nbr, nbr_link_data);
        }
    }
    return TRUE;
}

static an_walk_e 
an_acp_remove_nbrs_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    
    if (!nbr) {
        return (AN_WALK_FAIL);
    }

    an_acp_remove_to_nbr_for_all_valid_nbr_links(nbr);
    return (AN_WALK_SUCCESS);
}

static void 
an_acp_remove_for_all_valid_neighbors (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sRemove AN Control Plane for all bootstrapped nbrs " 
                 "walking the Nbr DB", an_bs_event);
    
    an_nbr_db_walk(an_acp_remove_nbrs_cb, NULL);
}

boolean 
an_acp_remove_ipsec_to_nbr_for_all_valid_nbr_links (an_nbr_t *nbr)
{
    an_list_element_t *elem = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    int i = 0;
    
    AN_FOR_ALL_DATA_IN_LIST(nbr->an_nbr_link_list, elem, nbr_link_data) {
        i++;
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "%sRemove ACP IPsec for all the valid nbr[%s] link [%d]", 
                     an_bs_event, nbr->udi.data, i); 
        an_acp_remove_ipsec_per_nbr_link(nbr, nbr_link_data);
    }
   
    return TRUE;
}

static an_walk_e 
an_acp_remove_ipsec_nbrs_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    
    if (!nbr) {
        return (AN_WALK_FAIL);
    }
    
    an_acp_remove_ipsec_to_nbr_for_all_valid_nbr_links(nbr);
    return (AN_WALK_SUCCESS);
}

static void
an_acp_remove_ipsec_for_all_valid_neighbors (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sRemove ACP IPsec for all bootstrapped nbrs "
                 "walking the Nbr DB", an_bs_event);
    
    an_nbr_db_walk(an_acp_remove_ipsec_nbrs_cb, NULL);
}

void an_acp_get_global_cap_set (uint16_t param_id) 
{
    switch (param_id) {
        case AN_ACP_CNP_PARAM_CHANNEL:
            if (an_set_channel_cli) {
                return;
            }
            an_acp_channel_cap_set.length = 1;
            an_acp_channel_cap_set.member_length = 1;
            if (an_acp_channel_cap_set.value) {
                an_free_guard(an_acp_channel_cap_set.value);
            }
            an_acp_channel_cap_set.value = 
                            an_malloc_guard(an_acp_channel_cap_set.length, 
                                            "AN Global channel cap set");
            if (!an_acp_channel_cap_set.value) {
                return;
            }
            an_acp_channel_cap_set.value[0] = AN_ACP_CHANNEL_GRE_IPV6;
            break;
        
        case AN_ACP_CNP_PARAM_SECURE:
            if (an_set_security_cli) {
                return;
            }
            an_acp_security_cap_set.length = 2;
            an_acp_security_cap_set.member_length = 1;
            if (an_acp_security_cap_set.value) {
                an_free_guard(an_acp_security_cap_set.value);
            }
            an_acp_security_cap_set.value = 
                            an_malloc_guard(an_acp_security_cap_set.length, 
                                            "AN Global secure cap set");
            if (!an_acp_security_cap_set.value) {
                return;
            }
            an_acp_security_cap_set.value[0] = AN_ACP_SEC_IPSEC;
            an_acp_security_cap_set.value[1] = AN_ACP_SEC_NONE;
        break;
        default:
        break;
    }
}
    
an_cnp_api_status_e
an_acp_get_cnp_set (an_cnp_capability_set_t *capability_set, an_addr_t src, 
                    an_addr_t dest, an_iptable_t iptable, an_if_t local_ifhndl)
{
    
    if (!capability_set || !capability_set->feat_id || 
        !capability_set->param_id) {
        return (AN_CNP_API_STATUS_BAD_ARGUMENTS);
    }
   
    an_acp_get_global_cap_set(capability_set->param_id);

    switch(capability_set->param_id) {
    case AN_ACP_CNP_PARAM_CHANNEL:
        capability_set->type = AN_CNP_DATA_TYPE_VECTOR;
        capability_set->u.vector.length = an_acp_channel_cap_set.length;
        capability_set->u.vector.member_length = 
                                           an_acp_channel_cap_set.member_length;
        capability_set->u.vector.value =
                   an_malloc_guard(capability_set->u.vector.length, "AN SMB ACP CNP");
        if (!capability_set->u.vector.value) {
            return (AN_CNP_API_STATUS_MEMORY_FAILURE);
        }
        an_memcpy(capability_set->u.vector.value, an_acp_channel_cap_set.value, 
                                                 an_acp_channel_cap_set.length);
        break;
    
    case AN_ACP_CNP_PARAM_SECURE:
        
        capability_set->type = AN_CNP_DATA_TYPE_VECTOR;
        capability_set->u.vector.length = an_acp_security_cap_set.length;
        capability_set->u.vector.member_length = 
                                        an_acp_security_cap_set.member_length;
        capability_set->u.vector.value =
                an_malloc_guard(capability_set->u.vector.length, "AN SMB ACP SEC CNP");
        if (!capability_set->u.vector.value) {
            return (AN_CNP_API_STATUS_MEMORY_FAILURE);
        }
        an_memcpy(capability_set->u.vector.value, an_acp_security_cap_set.value, 
                                                an_acp_security_cap_set.length);
        break;
    default:
        break;
    } 
        
    return (AN_CNP_API_STATUS_SUCCESS);
}

void 
an_test_acp_set_cap_values_from_param (uint16_t param_id, uint8_t value1, 
                                       uint8_t value2, uint8_t value3, 
                                       uint8_t value4) 
{
    switch(param_id) {
    case AN_ACP_CNP_PARAM_CHANNEL:
        an_acp_channel_cap_set.length = 4;
        an_acp_channel_cap_set.member_length = 1;
        if (an_acp_channel_cap_set.value) {
            an_free_guard(an_acp_channel_cap_set.value);
        }
        an_acp_channel_cap_set.value = 
              an_malloc_guard(an_acp_channel_cap_set.length, "AN test set cap");
        if (!an_acp_channel_cap_set.value) {
            return;
        }
        an_acp_channel_cap_set.value[0] = value1;
        an_acp_channel_cap_set.value[1] = value2;
        an_acp_channel_cap_set.value[2] = value3;
        an_acp_channel_cap_set.value[3] = value4;
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sTest CLI new acp capability set values for parameter "
                     "%s are, \n%41sval[0] = %d, val[1] = %d, val[2] = %d, "
                     "val[3] = %d, ", an_bs_event, 
                     an_acp_cnp_get_param_str(param_id), " ",
                     an_acp_channel_cap_set.value[0], 
                     an_acp_channel_cap_set.value[1],
                     an_acp_channel_cap_set.value[2], 
                     an_acp_channel_cap_set.value[3]);
        an_set_channel_cli = TRUE;
    break;
    
    case AN_ACP_CNP_PARAM_SECURE:
        an_acp_security_cap_set.length = 4;
        an_acp_security_cap_set.member_length = 1;
        if (an_acp_security_cap_set.value) {
            an_free_guard(an_acp_security_cap_set.value);
        }
        an_acp_security_cap_set.value =
              an_malloc_guard(an_acp_security_cap_set.length, "AN test set cap");
        if (!an_acp_security_cap_set.value) {
            return;
        }
        an_acp_security_cap_set.value[0] = value1;
        an_acp_security_cap_set.value[1] = value2;
        an_acp_security_cap_set.value[2] = value3;
        an_acp_security_cap_set.value[3] = value4;
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sTest CLI new acp capability set values for parameter "
                     "%s are, \n%41sval[0] = %d, val[1] = %d, val[2] = %d, "
                     "val[3] = %d, ", an_bs_event, 
                     an_acp_cnp_get_param_str(param_id), " ",
                     an_acp_security_cap_set.value[0], 
                     an_acp_security_cap_set.value[1],
                     an_acp_security_cap_set.value[2], 
                     an_acp_security_cap_set.value[3]);
        an_set_security_cli = TRUE;
    break;
    default:
    break;
    }
}
    
void an_test_acp_set_channel_default (void)
{
    if (an_acp_channel_cap_set.value) {
        an_free_guard(an_acp_channel_cap_set.value);
        an_acp_channel_cap_set.value = NULL;
    }
    
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sReset the acp channel capability set to default values",
                 an_bs_event);
    an_set_channel_cli = FALSE;
    an_acp_get_global_cap_set(AN_ACP_CNP_PARAM_CHANNEL);
}
    
void an_test_acp_set_security_default (void) 
{
    if (an_acp_security_cap_set.value) {
        an_free_guard(an_acp_security_cap_set.value);
        an_acp_security_cap_set.value = NULL;
    }
    
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sReset the acp security capability set to default values",
                 an_bs_event);
    an_set_security_cli = FALSE;
    an_acp_get_global_cap_set(AN_ACP_CNP_PARAM_SECURE);
}

an_cnp_api_status_e
an_acp_learnt_cnp_set (an_cnp_capability_set_t *capability_set, an_addr_t src, 
                       an_addr_t dest, an_iptable_t iptable, an_if_t local_ifhndl)
{
    if (!capability_set || !capability_set->feat_id || 
        !capability_set->param_id) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sError!!!Invalid negotiated feature parameters", 
                     an_bs_event);
        return (AN_CNP_API_STATUS_BAD_ARGUMENTS);
    }

    if ((capability_set->type != AN_CNP_DATA_TYPE_SCALAR) || 
            !capability_set->u.scalar.length || 
            !capability_set->u.scalar.value[0] ) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sError!!!Invalid capability set params while "
                     "learning cap set ", an_bs_event);
        return (AN_CNP_API_STATUS_BAD_ARGUMENTS);
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sLearnt ACP capabilities from CNP are " 
                 "parameter = %s, value = %d ", an_bs_event, 
                 an_acp_cnp_get_param_str(capability_set->param_id), 
                 capability_set->u.scalar.value[0]);
                    
    return (AN_CNP_API_STATUS_SUCCESS);
}

an_walk_e
an_acp_update_nego_acp_info_cbs (an_avl_node_t *node, void *nego_info)
{
    an_nbr_t *nbr = (an_nbr_t *)node;

    if (!nbr) {
        return (AN_WALK_FAIL);
    }

    an_list_element_t *elem = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    an_acp_negotiated_info_t *nego_det = NULL;
    nego_det = (an_acp_negotiated_info_t *)nego_info;
    
     AN_FOR_ALL_DATA_IN_LIST(nbr->an_nbr_link_list, elem, nbr_link_data) {
        if (nbr_link_data != NULL &&
            (nbr_link_data->local_ifhndl == nego_det->local_ifhndl) &&
            (an_memcmp(&nbr_link_data->ipaddr, &nego_det->nbr_addr, 
                                                sizeof(an_addr_t))== 0)) {
            
            switch(nego_det->cap_set.param_id) {
                 
                case AN_ACP_CNP_PARAM_CHANNEL: 
                    nbr_link_data->acp_info.channel_negotiated = 
                                            nego_det->cap_set.u.vector.value[0];
                    an_acp_create_per_nbr_link(nbr, nbr_link_data);
                break;

                case AN_ACP_CNP_PARAM_SECURE:
                    nbr_link_data->acp_info.sec_negotiated = 
                                            nego_det->cap_set.u.vector.value[0];
                    an_acp_create_ipsec_per_nbr_link(nbr, nbr_link_data);
                break;
            
                default:
                break;
            }
        }
    }
    return (AN_WALK_SUCCESS);
}
    

void
an_acp_update_negotiated_nbr_acp_info (an_acp_negotiated_info_t nego_info)
{
    an_nbr_db_walk(an_acp_update_nego_acp_info_cbs, &nego_info);
}

an_cnp_api_status_e
an_acp_negotiated_cnp_set (an_cnp_capability_set_t *capability_set, 
                           an_addr_t src, an_addr_t dest, 
                           an_iptable_t iptable, an_if_t local_ifhndl)
{
    an_acp_negotiated_info_t negotiated_info = {};

    if (!capability_set || !capability_set->feat_id || 
        !capability_set->param_id) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sError!!!Invalid negotiated feature parameters", 
                     an_bs_event);
        return (AN_CNP_API_STATUS_BAD_ARGUMENTS);
    }
    
    if (capability_set->type == AN_CNP_DATA_TYPE_SCALAR) {
        if (!capability_set->u.scalar.length || 
            !capability_set->u.scalar.value[0]){
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sError!!!Invalid capability set scalar parameters", 
                         an_bs_event);
            return (AN_CNP_API_STATUS_BAD_ARGUMENTS);
        }
        
    } else if (capability_set->type == AN_CNP_DATA_TYPE_VECTOR) {
        if (!capability_set->u.vector.length || 
            !capability_set->u.vector.value ||
            !capability_set->u.vector.member_length) {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sError!!!Invalid capability set vector parameters", 
                     an_bs_event);
            return (AN_CNP_API_STATUS_BAD_ARGUMENTS);
        }
    } else {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sError!!!Invalid capability type", an_bs_event);
            return (AN_CNP_API_STATUS_BAD_ARGUMENTS);
    }

   
    an_memset(&negotiated_info, 0, sizeof(an_acp_negotiated_info_t)); 
    negotiated_info.cap_set.param_id = capability_set->param_id;
    negotiated_info.ip_table = iptable;
    negotiated_info.nbr_addr = dest;
    negotiated_info.local_ifhndl = local_ifhndl;
    
    if (capability_set->type == AN_CNP_DATA_TYPE_SCALAR) {
        negotiated_info.cap_set.u.scalar.value = capability_set->u.scalar.value;
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNegotiated ACP channel capabilities on %s from CNP "
                     "are parameter = %s, value = %s", an_bs_event, 
                     an_if_get_name(negotiated_info.local_ifhndl),
                     an_acp_cnp_get_param_str(capability_set->param_id),
                     an_acp_get_value_string(capability_set));
    } else if (capability_set->type == AN_CNP_DATA_TYPE_VECTOR) {
        negotiated_info.cap_set.u.vector.value = capability_set->u.vector.value;
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNegotiated ACP security capabilities on %s from CNP "
                     "are parameter = %s, value = %s", an_bs_event, 
                     an_if_get_name(negotiated_info.local_ifhndl),
                     an_acp_cnp_get_param_str(capability_set->param_id),
                     an_acp_get_value_string(capability_set));
    }
    
    an_acp_update_negotiated_nbr_acp_info(negotiated_info);

    return (AN_CNP_API_STATUS_SUCCESS);
}

an_cnp_api_status_e
an_acp_learn_cnp_error (an_cnp_error_t *error, 
                        an_cnp_capability_set_t *capability_set, an_addr_t src, 
                        an_addr_t dest, an_iptable_t iptable, an_if_t ifhndl)
{
    if (!error->feat_id || !error->param_id) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sError!!!Invalid CNP error parameters", an_bs_event);
        return (AN_CNP_API_STATUS_BAD_ARGUMENTS);
    }

    if (error->error_id == AN_CNP_ERROR_PENDING) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sLearn for ACP capabilities from CNP is pending",
                     an_bs_event);
    }

    return (AN_CNP_API_STATUS_SUCCESS);
}

void
an_acp_negotiate_security_type_per_nbr_link (an_nbr_t *nbr, 
                                             an_nbr_link_spec_t *nbr_link_data)
{
    an_addr_t addr_src = AN_ADDR_ZERO;
    an_cnp_api_status_e status = 0;

    if (nbr == NULL)
        return;

    an_addr_set_from_v6addr(&addr_src, 
                            an_ipv6_get_ll(nbr_link_data->local_ifhndl));
    status = an_cnp_negotiate(AN_CNP_FEAT_ID_ACP, AN_ACP_CNP_PARAM_SECURE,
                              nbr_link_data->ipaddr, addr_src, 
                              an_get_iptable(), nbr_link_data->local_ifhndl);
                                 
    if (status != AN_CNP_API_STATUS_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL, 
                     "\n%sAN control plane negotiation for feature[%s] and " 
                     "parameter[%s] with \n%41snbr[%s] on interface %s "
                     "addressed %s \n%41sreturned status %s", an_bs_event,
                     "AN_CNP_FEAT_ID_ACP", "AN_ACP_CNP_PARAM_SECURE", 
                     nbr->udi.data, an_addr_get_string(&nbr_link_data->ipaddr), " ",  
                     an_if_get_name(nbr_link_data->local_ifhndl), " ",
                     an_cnp_get_api_status_names(status));
        return;
    }
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL, 
                 "\n%sAN control plane negotiation for feature[%s] and " 
                 "parameter[%s] with \n%41snbr[%s] on interface %s addressed %s"
                 "\n%41sreturned status %s", an_bs_event,
                 "AN_CNP_FEAT_ID_ACP", "AN_ACP_CNP_PARAM_CHANNEL", 
                 nbr->udi.data, an_addr_get_string(&nbr_link_data->ipaddr), " ",  
                 an_if_get_name(nbr_link_data->local_ifhndl), " ",
                 an_cnp_get_api_status_names(status));

    return;
}

boolean
an_acp_cnp_init (void)
{
    an_cnp_feature_descr_t feat_descr = {};
    an_cnp_api_status_e cnp_api_status;

    feat_descr.feat_id = AN_CNP_FEAT_ID_ACP;
    feat_descr.get_cap_set = an_acp_get_cnp_set;
    feat_descr.learnt_set = an_acp_learnt_cnp_set;
    feat_descr.negotiated_set = an_acp_negotiated_cnp_set;
    feat_descr.report_error = an_acp_learn_cnp_error;
    
    cnp_api_status = an_cnp_register(feat_descr);
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sACP Feature(Feat Id = %s) registration with the " 
                 "Common Negotiation Protocol returned status %s", an_bs_event, 
                 "AN_CNP_FEAT_ID_ACP", 
                 an_cnp_get_api_status_names(cnp_api_status));

    return (TRUE);

}

boolean 
an_acp_cnp_uninit (void) 
{
    an_cnp_feature_descr_t feat_descr = {};
    uint8_t name[20] = "AN acp cap Discovery";
    an_cnp_api_status_e cnp_api_status;

    an_memcpy(feat_descr.name, name, an_strnlen(name, 20));
    feat_descr.feat_id = AN_CNP_FEAT_ID_ACP;
    feat_descr.get_cap_set = an_acp_get_cnp_set;
    feat_descr.learnt_set = an_acp_learnt_cnp_set;
    feat_descr.negotiated_set = an_acp_negotiated_cnp_set;
    feat_descr.report_error = an_acp_learn_cnp_error;
    
    cnp_api_status = an_cnp_unregister(feat_descr);
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sACP Feature(Feat Id = %s) Un-registration with the " 
                 "Common Negotiation Protocol returned status %s", an_bs_event, 
                 "AN_CNP_FEAT_ID_ACP", 
                 an_cnp_get_api_status_names(cnp_api_status));

    return (TRUE);
}

void
an_acp_init (void)
{ 
    an_cerrno rc = EOK;
    an_routing_cfg_t routing_info;

    an_memset(&routing_info, 0, sizeof(routing_info));
    /* Make sure that the previous ACP instance is brought down first */
    an_acp_uninit();
    an_acp_cnp_init();

    rc = an_avl_init(&an_acp_client_tree, an_acp_client_compare);
    if (CERR_IS_NOTOK(rc)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%s AN ACP Client DB Init Failed", an_bs_event);
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sBringing up AN control plane globally", an_bs_event);

    an_set_afi(AN_AF_IPv6);

    /* Bring up Routing */
    if (an_routing_ospf) {
      routing_info.ospf_pid = 1;
      routing_info.ospf_area = 100;
      routing_info.ospf_rid = 
              an_get_v4addr_from_names(an_get_domain_id(), an_get_device_id());
      an_set_routing_ospf_pid(routing_info.ospf_pid);
      an_set_routing_ospf_area(routing_info.ospf_area);
      an_set_routing_ospf_rid(routing_info.ospf_rid);

    } else {
      an_set_rpl_routing_info();
      routing_info.an_rpl_info = an_get_rpl_routing_info();
    }

    an_acp_routing_init();
    an_acp_routing_enable(routing_info);
    an_acp_routing_track_anra();
    an_ipv6_unicast_routing_enable_disable_register();

    /* Bring up loopback with routing*/
    an_config_loopback();
    an_acp_initialized = TRUE;

    /*IKEv2 functions */
    an_ikev2_define_profile_names(0);
    an_ikev2_profile_init();
    
    /* IPSEC functions */
    an_ipsec_define_profile_name();
    an_ipsec_profile_init();
    
    /* Bring up ACP per neighbor with routing */
    an_acp_create_for_all_valid_neighbors();

    an_event_acp_initialized();
    /* NMS  */
    /* If command is given make the interface ready to connect to server */
    an_acp_init_connection_device_bootstrapped();

}

void
an_acp_uninit (void)
{
    an_routing_cfg_t routing_info;
    routing_info = an_get_routing_info(); 
    if(!an_acp_is_initialized())
    {
       DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                    "\n%sError!!!AN Control Plane not yet up globally ", 
                    an_bs_event);
       return;
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sBringing down AN control plane", an_bs_event);   
    an_ipv6_unicast_routing_enable_disable_unregister();
    an_acp_routing_disable(routing_info);
    an_acp_routing_uninit();


    //Cleanup to be done before ACP down
    an_event_acp_pre_uninitialization();

    an_acp_remove_ipsec_for_all_valid_neighbors();
    an_acp_remove_for_all_valid_neighbors();

    /*Remove IKev2 profile*/
    an_ikev2_profile_uninit();
    an_ikev2_clear_profile_names();

    /*Remove IPSec profile*/
    an_ipsec_profile_uninit();
    an_ipsec_clear_profile_name();
    
    an_unconfig_loopback();

    if (an_routing_ospf)
    {
      an_set_routing_ospf_pid(0);
      an_set_routing_ospf_area(0);
      an_set_routing_ospf_rid(0);
    }
    else
    {
      an_reset_rpl_routing_info();
    }
    an_acp_initialized = FALSE;

    /*NMS */
    an_acp_uninit_connection();
   
    an_avl_uninit(&an_acp_client_tree);
    an_event_acp_uninitialized();

}

an_acp_ext_conn_e
an_acp_connect_state_get (an_if_t ifhndl)
{
    an_if_info_t *an_if_info = NULL;

    /* Interface Level */
    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
        return AN_EXT_CONNECT_STATE_NO;
    }

    return (an_if_info->an_if_acp_info.ext_conn_state);
}

static void
an_acp_connect_state_set (an_if_t ifhndl, an_acp_ext_conn_e ext_conn_state)
{
    an_if_info_t *an_if_info = NULL;

    /* Interface Level */
    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sError!!!While setting AN Control Plane connect state "
                     "to %s, failed to search that interface in IF INFO DB",
                     an_bs_event, an_if_get_name(ifhndl));
        return;
    }

    an_if_info->an_if_acp_info.ext_conn_state = ext_conn_state;
    return;
}

boolean
an_acp_init_external_connection (an_if_t ifhndl)
{
    an_routing_cfg_t routing_info;
    uint8_t *sudi_keypair_label = NULL;
        
    if (!ifhndl) {
        return (FALSE);
    }
        
   if (an_if_is_layer2(ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sNo support on L2 interface %s",
                         an_bs_event, an_if_get_name(ifhndl));
        return FALSE;
    } 
    /* If acp if not already initialized, put the command on hold */
    if (FALSE == an_acp_initialized) {  
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sSetting AN control plane connect state to %s on %s",
                     an_bs_event, "AN_EXT_CONNECT_STATE_HOLD", 
                     an_if_get_name(ifhndl));
        an_acp_connect_state_set(ifhndl, AN_EXT_CONNECT_STATE_HOLD);
        return (TRUE);
    }

    /* Unitialize configurations on the interface */

    /* Initialize configurations to make the interface external connection ready */    
    an_nd_set_preference(ifhndl, AN_ND_CLIENT_CONNECT, AN_ND_CFG_DISABLED);
    an_nd_startorstop(ifhndl);

    if (!an_ipv6_enable_on_interface(ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to enable IPv6 on the interface [%s]",
                     an_bs_event, an_if_get_name(ifhndl));
        return (FALSE);
    }

    if (!an_sudi_get_keypair_label(&sudi_keypair_label)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sSudi Keypair Label doesn't exist", an_nd_event);
    }
    
    an_ipv6_send_init_on_interface_with_secmode_transit(ifhndl, 
            sudi_keypair_label);

    routing_info = an_get_routing_info();
    an_acp_routing_enable_on_interface(ifhndl, routing_info);
  
   DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%sSetting AN control plane connect state to %s on %s",
                an_bs_event, "AN_EXT_CONNECT_STATE_DONE", 
                an_if_get_name(ifhndl));
    an_acp_connect_state_set(ifhndl, AN_EXT_CONNECT_STATE_DONE);
    return (TRUE);
}

boolean
an_acp_hold_external_connection (an_if_t ifhndl)
{
    an_routing_cfg_t routing_info;
    uint8_t *sudi_keypair_label = NULL;   
    
    if (an_if_is_layer2(ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sNo support on L2 interface %s",
                         an_bs_event, an_if_get_name(ifhndl));
        return FALSE;
    }

    /* Unitialize configurations on the interface */
    an_nd_set_preference(ifhndl, AN_ND_CLIENT_CONNECT, AN_ND_CFG_DEFAULT);
    an_nd_startorstop(ifhndl);

    /*an_ipv6_send_change_nd_mode(ifhndl, IPV6_SEND_SECMODE_FULL_SECURE);*/
    if (!an_ipv6_enable_on_interface(ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to enable ipv6 on interface %s", an_bs_event,
                     an_if_get_name(ifhndl));
        return (FALSE);
    }

    if (!an_sudi_get_keypair_label(&sudi_keypair_label)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sSudi Keypair Label doesn't exist", an_nd_event);
    }
    
    an_ipv6_send_init_on_interface(ifhndl, sudi_keypair_label);
    
    routing_info = an_get_routing_info();
    an_acp_routing_disable_on_interface(ifhndl, routing_info);

    an_acp_connect_state_set(ifhndl, AN_EXT_CONNECT_STATE_HOLD); 
    return (TRUE);
}

boolean
an_acp_uninit_external_connection (an_if_t ifhndl)
{
    an_routing_cfg_t routing_info;
    uint8_t *sudi_keypair_label = NULL;
    
    if (!ifhndl) {
        return (FALSE);
    }
    if (an_if_is_layer2(ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sNo support on L2 interface %s",
                         an_bs_event, an_if_get_name(ifhndl));
        return FALSE;
    }

    /*an_ipv6_send_change_nd_mode(ifhndl, IPV6_SEND_SECMODE_FULL_SECURE);*/

    /* Unitialize configurations on the interface */   
    an_nd_set_preference(ifhndl, AN_ND_CLIENT_CONNECT, AN_ND_CFG_DEFAULT);
    an_nd_startorstop(ifhndl);

    if (!an_ipv6_enable_on_interface(ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to enable ipv6 on interface %s", an_bs_event,
                     an_if_get_name(ifhndl));
        return (FALSE);
    }

    if (!an_sudi_get_keypair_label(&sudi_keypair_label)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%ssUDI keypair label doesn't exist", an_nd_event);
    }
    
    an_ipv6_send_init_on_interface(ifhndl, sudi_keypair_label);
    
    routing_info = an_get_routing_info();
    an_acp_routing_disable_on_interface(ifhndl, routing_info);
    
    an_acp_connect_state_set(ifhndl, AN_EXT_CONNECT_STATE_NO);
    return (TRUE);
}

static an_walk_e
an_acp_init_connection_device_bootstrapped_cb (an_avl_node_t *node, void *data)
{
    an_if_info_t *an_if_info = NULL;

    if (!node) {
        return (AN_WALK_FAIL);
    }
    an_if_info = (an_if_info_t *)node;

    if (an_if_info->an_if_acp_info.ext_conn_state == AN_EXT_CONNECT_STATE_HOLD) {
        an_acp_init_external_connection(an_if_info->ifhndl);
    }

    return (AN_WALK_SUCCESS);
}

void
an_acp_init_connection_device_bootstrapped (void)
{
    an_if_info_db_walk(an_acp_init_connection_device_bootstrapped_cb, NULL);
}

an_walk_e
an_acp_uninit_connection_cb (an_avl_node_t *node, void *data)
{
    an_if_info_t *an_if_info = NULL;

    if (!node) {
        return (AN_WALK_FAIL);
    }
    an_if_info = (an_if_info_t *)node;

    if (an_if_info->an_if_acp_info.ext_conn_state == AN_EXT_CONNECT_STATE_DONE) {
        an_acp_hold_external_connection(an_if_info->ifhndl);
    }

    return (AN_WALK_SUCCESS);
}

void
an_acp_uninit_connection (void)
{
    an_if_info_db_walk(an_acp_uninit_connection_cb, NULL);
}

boolean
an_acp_is_initialized (void)
{
    return (an_acp_initialized);
}


boolean
an_acp_is_up_on_nbr_link (an_nbr_link_spec_t *nbr_link_data) 
{
   if (nbr_link_data->acp_info.channel_type != AN_ACP_CHANNEL_NONE)
   {
       return (TRUE);
   }else {
       return (FALSE);
   }
}

boolean 
an_acp_is_up_on_nbr (an_nbr_t *nbr)
{
   an_list_element_t *elem = NULL;
   an_nbr_link_spec_t *nbr_link_data = NULL;
                       
   AN_FOR_ALL_DATA_IN_LIST(nbr->an_nbr_link_list, elem, nbr_link_data) {
      if (nbr_link_data->acp_info.channel_type != AN_ACP_CHANNEL_NONE)
      {
          return (TRUE);
      }
   }
   return FALSE;
               
}

void 
an_acp_ntp_peer_remove_global(an_nbr_t *nbr)
{
    an_list_element_t *elem = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    an_ntp_peer_param_t ntp_peer;

    an_memset((uint8_t *)&ntp_peer, 0, sizeof(an_ntp_peer_param_t));

    /* Remove ntp peer created on link local */
    AN_FOR_ALL_DATA_IN_LIST(nbr->an_nbr_link_list, elem, nbr_link_data) {
        ntp_peer.peer_addr = nbr_link_data->ipaddr;
        ntp_peer.ifhdl = nbr_link_data->local_ifhndl;
        (void)an_ntp_remove_peer(&ntp_peer);
    }

}

void
an_acp_enable_clock_sync(an_nbr_t *nbr)
{
    an_ntp_peer_param_t ntp_peer;
    
    an_memset((uint8_t *)&ntp_peer, 0, sizeof(an_ntp_peer_param_t));

    /* Create ntp peer over acp */
    ntp_peer.peer_addr = an_get_v6addr_from_names(nbr->domain_id, 
                                                  nbr->device_id);
    ntp_peer.ifhdl = an_source_if;
    (void)an_ntp_set_peer(&ntp_peer);
    return;
               
}
