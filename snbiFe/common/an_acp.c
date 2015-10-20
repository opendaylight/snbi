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
#include "an_anra.h"
#include "an_event_mgr.h"
//#include "an_topo_disc.h"
#include "an_cnp.h"
#include "../al/an_ipsec.h"
#include "../al/an_dike.h"
#include "../al/an_ike.h"
#include "../al/an_syslog.h"

//#include "../ios/an_service_discovery.h"
#define AN_ACP_TUNN_MODE_GRE_IPV6 21
#define AN_LOOPBACK_NUM_START 100000
#define AN_LOOPBACK_NUM_END 2147483647
#define AN_DIKE_LOCAL_PORT 5000
#define AN_DIKE_REMOTE_PORT 5000

uint16_t an_routing_ospf = 0;
an_if_t an_source_if;

uint32_t an_loopback_id = AN_LOOPBACK_NUM_START;

static void an_acp_connect_state_set(an_if_t ifhndl,
                an_acp_ext_conn_e ext_conn_state);

boolean an_acp_initialized = FALSE;
static an_addr_t prev_anra_ip; 
extern boolean an_set_secure_channel_cli;

const uint8_t *an_acp_client_status_enum_string [] = {
    "None",
    "AN ACP Client success",
    "Parameters are invalid",
    "ACP Client already registered",
    "ACP Client not registered",
    "Client handle mismatch",
    "Failed to allocate memory",
    "Client db full",
    "Invalid interface",
    "AN acp client enum max",
};

const uint8_t *
an_acp_client_status_enum_get_string (an_acp_client_status_e enum_type)
{
    return (an_acp_client_status_enum_string[enum_type]);
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

an_avl_walk_e
an_acp_client_db_init_cb (an_avl_node_t *node, void *args)
{
    an_acp_client_t *client = (an_acp_client_t *)node;

    if (!client) {
        return (AN_AVL_WALK_FAIL);
    }

    an_acp_client_db_remove(client);
    an_acp_client_free(client);

    return (AN_AVL_WALK_SUCCESS);
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
    if (client_comm->ifhndl) {
        if (!an_if_is_acp_interface(client_comm->ifhndl))
        return (AN_ACP_CLIENT_INVALID_IF);
    }          
    message = an_msg_mgr_get_empty_message_package();
    if (!message) {
        return (AN_ACP_CLIENT_MEM_FAILURE);
    }

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
        an_msg_mgr_free_message_package(message);
        return (AN_ACP_CLIENT_MEM_FAILURE);
    }
    an_memcpy_guard_s(message->payload.data, message->payload.len,
                         client_comm->payload.data, client_comm->payload.len); 
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
        an_msg_mgr_free_message_package(acp_message);
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

#if 0
void
an_acp_routing_init (void)
{
    uint8_t commands[20][100] = {};
    an_ipv6_routing_start_global_unicast();
    an_rwatch_init();

    //TBD: AN-PATCH
    snprintf(&commands[0][0], 100, "configure terminal");
    snprintf(&commands[1][0], 100, "no ipv6 cef");
    snprintf(&commands[2][0], 100, "end");

    uint8_t (*command)[100] = commands;
    an_execute_command(command, 3);

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sInitialized Global Unicast Routing", an_bs_event);
}

void
an_acp_routing_uninit (void)
{
    uint8_t commands[20][100] = {};

    an_ipv6_routing_stop_global_unicast();
    an_rwatch_uninit();

    // TBD: AN-PATCH
    snprintf(&commands[0][0], 100, "configure terminal");
    snprintf(&commands[1][0], 100, "ipv6 cef");
    snprintf(&commands[2][0], 100, "end");
     
    uint8_t (*command)[100] = commands;
    an_execute_command(command, 3);
 
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sUninitialized Global IPv6 Unicast Routing", an_bs_event);
}

void
an_acp_routing_enable (an_routing_cfg_t routing_info)
{
    uint8_t commands[20][100] = {};

    if (an_routing_ospf) {
        snprintf(&commands[0][0], 100, "configure terminal");
        snprintf(&commands[1][0], 100, "router ospfv3 %d", 
                                       routing_info.ospf_pid);
        snprintf(&commands[2][0], 100, "router-id %i", routing_info.ospf_rid);
        //    snprintf(&commands[3][0], 100, "address-family ipv6 unicast");
        //    snprintf(&commands[4][0], 100, "exit");
        snprintf(&commands[3][0], 100, "address-family ipv6 unicast vrf an");
        snprintf(&commands[4][0], 100, "end");

        uint8_t (*command)[100] = commands;
        an_execute_command(command, 5);
        an_syslog(AN_SYSLOG_ACP_ROUTING_GLOBAL_ENABLED, 
                        routing_info.ospf_pid, routing_info.ospf_rid,
                        routing_info.ospf_area);    
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sEnabled OSPF routing globally", an_bs_event);

    } else {
        an_rpl_global_enable(&routing_info.an_rpl_info);
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sEnabled RPL routing globally", an_bs_event);
}

void
an_acp_routing_enable_on_interface (an_if_t ifhndl, 
                                    an_routing_cfg_t routing_info)
{
    uint8_t commands[20][100] = {};
    an_if_info_t *an_if_info = NULL;

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    an_if_set_routing_required(an_if_info);

    if (an_routing_ospf) {
        snprintf(&commands[0][0], 100, "configure terminal");
        snprintf(&commands[1][0], 100, "interface %s", an_if_get_name(ifhndl));
        snprintf(&commands[2][0], 100, "ospfv3 %d ipv6 area %d", 
                 routing_info.ospf_pid, routing_info.ospf_area);
        snprintf(&commands[3][0], 100, "exit");
        snprintf(&commands[4][0], 100, "exit");

        uint8_t (*command)[100] = commands;
        an_execute_command(command, 5);
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sEnabled OSPF on the interface %s", 
                     an_bs_event, an_if_get_name(ifhndl));

    } else {
        an_rpl_interface_enable(routing_info.an_rpl_info.tag_name, 
                                ifhndl);
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sEnabled RPL on the interface %s", 
                     an_bs_event, an_if_get_name(ifhndl));
    }
}

void
an_acp_routing_disable_on_interface (an_if_t ifhndl, 
                                     an_routing_cfg_t routing_info)
{
    uint8_t commands[20][100] = {};
    an_if_info_t *an_if_info = NULL;

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    an_if_unset_routing_required(an_if_info);

    if (an_routing_ospf) /* Enable OSPF for AN */
    {
    snprintf(&commands[0][0], 100, "configure terminal");
    snprintf(&commands[1][0], 100, "interface %s", an_if_get_name(ifhndl));
    snprintf(&commands[2][0], 100, "no ospfv3 %d ipv6 area %d",
             routing_info.ospf_pid, routing_info.ospf_area);
    snprintf(&commands[3][0], 100, "exit");
    snprintf(&commands[4][0], 100, "exit");

    uint8_t (*command)[100] = commands;
    an_execute_command(command, 5);
    an_syslog(AN_SYSLOG_ACP_ROUTING_INTERFACE_ENABLED, 
                    an_if_get_name(ifhndl),routing_info.ospf_pid,
                    routing_info.ospf_rid,routing_info.ospf_area);
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sDisabled OSPF on the interface %s", 
                     an_bs_event, an_if_get_name(ifhndl));
    
    }
    else /* Disable RPL for AN */
    {
       an_rpl_interface_disable(routing_info.an_rpl_info.tag_name, ifhndl);
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sDisabled RPL on the interface %s", 
                     an_bs_event, an_if_get_name(ifhndl));
    }
}
#endif

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

boolean
an_acp_is_vrf_applicable (void)
{
 return(an_acp_cnp_is_vrf_applicable()); 
}

static boolean
an_config_loopback_cb (an_if_t ifhndl)
{
    an_addr_t addr = AN_ADDR_ZERO;
    an_routing_cfg_t routing_info = {};
    an_vrf_info_t *vrf_info = NULL;
  
    vrf_info = an_vrf_get(); 
 
    if (!an_if_is_up(ifhndl)) {
        return (TRUE);
    }

    if (an_if_is_loopback(ifhndl)) {

        /* Disable AN ND in ACP */

        an_nd_set_preference(ifhndl, AN_ND_CLIENT_INTERFACE_TYPE, AN_ND_CFG_DISABLED);
        an_nd_startorstop(ifhndl);

        an_if_make_volatile(ifhndl);

        if (an_acp_is_vrf_applicable()) {
            if (!an_vrf_configure_interface(ifhndl)) {
                DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                             "\n%sFailed to set up vrf on interface %s", 
                             an_bs_event, an_if_get_name(ifhndl));
                an_syslog(AN_SYSLOG_ACP_VRF_INTERFACE_CREATE_FAIL, 
                          an_if_get_name(ifhndl), vrf_info->an_vrf_name, 
                          vrf_info->an_vrf_id);
                return (FALSE);
            }
            an_syslog(AN_SYSLOG_ACP_VRF_INTERFACE_CREATE_SUCCESS, 
                      an_if_get_name(ifhndl), vrf_info->an_vrf_name, 
                      vrf_info->an_vrf_id);
        }

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

void
an_unconfig_loopback (void)
{
    an_if_t lb_ifhndl = 0;
    an_if_info_t *if_info = NULL;

    lb_ifhndl = an_get_autonomic_loopback_ifhndl();

    if_info = an_if_info_db_search(lb_ifhndl, FALSE);
    if (if_info) {
        if_info->autonomically_created = FALSE;
        an_if_info_db_remove(if_info);
        an_if_info_free(if_info);
    }
    an_if_remove_loopback(lb_ifhndl);
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sUnconfigured Loopback %d", an_bs_event, an_loopback_id);
}

an_if_t
an_acp_tunnel_create_and_configure (an_addr_t src_ip, an_addr_t dst_ip, 
                                an_if_t src_if)
{
    uint8_t tunn_mode = AN_ACP_TUNN_MODE_GRE_IPV6;
    an_if_t tunn_ifhndl = 0;
    an_routing_cfg_t routing_info;
    an_vrf_info_t *vrf_info = NULL;
 	an_v6addr_t an_ll_scope_all_node_mcast_v6addr = AN_V6ADDR_ZERO;	

    vrf_info = an_vrf_get();
    an_memset_s(&routing_info, 0, sizeof(routing_info));
    tunn_ifhndl = an_tunnel_create(&src_ip, &dst_ip, src_if, tunn_mode);
    if (!tunn_ifhndl) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sFailed to create tunnel for "
                     "AN Control Plane channel", an_bs_event);
        return (0);
    }

    
    if (!an_vrf_configure_interface(tunn_ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sFailed to setup vrf for AN Control Plane channel", 
                     an_bs_event);
        an_syslog(AN_SYSLOG_ACP_VRF_INTERFACE_CREATE_FAIL, 
                  an_if_get_name(tunn_ifhndl), vrf_info->an_vrf_name, 
                  vrf_info->an_vrf_id);
        an_tunnel_remove(tunn_ifhndl);
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
    an_nd_set_preference(tunn_ifhndl, AN_ND_CLIENT_INTERFACE_TYPE,
                         AN_ND_CFG_DISABLED);
    an_nd_startorstop(tunn_ifhndl);

	an_ll_scope_all_node_mcast_v6addr = 
					an_addr_get_v6addr(an_ll_scope_all_node_mcast);
    an_ipv6_join_mld_group(tunn_ifhndl,
                           (an_v6addr_t *)&an_ll_scope_all_node_mcast_v6addr);
    //an_if_make_volatile(tunn_ifhndl);
    return (tunn_ifhndl);
}

void 
an_acp_tunnel_unconfigure_and_delete (an_if_t tunn_ifhndl)
{
    if (!tunn_ifhndl) {
        return;
    }
    an_routing_cfg_t routing_info = {};    
    routing_info = an_get_routing_info();
    an_acp_routing_disable_on_interface(tunn_ifhndl, routing_info);
    
    if (!an_ipv6_disable_on_interface(tunn_ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to disable IPV6 on AN control plane tunnel %s",
                     an_bs_event, an_if_get_name(tunn_ifhndl));
    }

    if (!an_vrf_unconfigure_interface(tunn_ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to remove vrf on ACP channel interface %s",
                     an_bs_event, an_if_get_name(tunn_ifhndl));
    }
    an_tunnel_remove(tunn_ifhndl);
}

an_if_t
an_acp_get_acp_if_on_nbr_link (an_nbr_t *nbr, 
                                  an_nbr_link_spec_t *nbr_link_data)
{
    an_if_t acp_if = 0;

    if (!nbr || !nbr_link_data) {
        return (0);
    }
    
    if (!nbr_link_data->acp_info.sec_channel_established) {
        return (0);
    }

    switch (nbr_link_data->acp_info.sec_channel_established) {
    case AN_ACP_IPSEC_ON_PHY:
        acp_if = nbr_link_data->acp_info.sec_channel_spec.sec_phy_info.phy_channel.ifhndl;
        break;

    case AN_ACP_NOSEC_ON_PHY:
        acp_if = nbr_link_data->acp_info.sec_channel_spec.nosec_phy_info.phy_channel.ifhndl;
        break;

    case AN_ACP_IPSEC_ON_GRE:
        acp_if = nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.ifhndl;

        break;

    case AN_ACP_DIKE_ON_GRE:
        acp_if = nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.ifhndl;
        break;

    case AN_ACP_NOSEC_ON_GRE:
        acp_if = nbr_link_data->acp_info.sec_channel_spec.nosec_gre_info.gre_channel.ifhndl;
        break;

    default:
        acp_if = 0;
        break;
    }

    return (acp_if);
}

static void
an_acp_remove_ipsec_on_gre_tunnel (an_nbr_t *nbr,
                                   an_nbr_link_spec_t *nbr_link_data)
{
    an_acp_sec_on_gre_info_t sec_gre_info;
    boolean tunnel_mode = FALSE;

    if (!nbr || !nbr_link_data) {
        return;
    }
    
    sec_gre_info = nbr_link_data->acp_info.sec_channel_spec.sec_gre_info;
    tunnel_mode = sec_gre_info.sec_spec.ipsec_info.tunnel_mode;
    
    if (tunnel_mode &&
        (sec_gre_info.gre_channel.state == AN_ACP_TUNN_CREATED_UP) &&
        sec_gre_info.gre_channel.ifhndl) {
       
         //ipsec cleanup
        an_ipsec_remove_on_tunnel(sec_gre_info.gre_channel.ifhndl);
        an_syslog(AN_SYSLOG_ACP_IPSEC_TO_NBR_REMOVED,
                  an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                  nbr_link_data)), nbr->udi.data,
                  an_if_get_name(nbr_link_data->local_ifhndl));
        
        // tunnel removal 
        an_acp_tunnel_unconfigure_and_delete(sec_gre_info.gre_channel.ifhndl);
        an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_REMOVED,
                  an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                  nbr_link_data)), nbr->udi.data,
                  an_if_get_name(nbr_link_data->local_ifhndl));
        
        an_event_acp_on_nbr_link_removed(nbr, nbr_link_data); 
        an_acp_init_acp_info_per_nbr_link(nbr_link_data);
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to remove %s secure channel to Nbr[%s] ",
                     an_bs_event, "AN_ACP_IPSEC_ON_GRE", nbr->udi.data);
    }
    

    return;
}

static void 
an_acp_remove_dike_on_gre_tunnel (an_nbr_t *nbr,
                                   an_nbr_link_spec_t *nbr_link_data)
{
    an_acp_sec_on_gre_info_t sec_gre_info;
    boolean tunnel_mode = FALSE;

    if (!nbr || !nbr_link_data) {
        return;
    }
    
    sec_gre_info = nbr_link_data->acp_info.sec_channel_spec.sec_gre_info;
    tunnel_mode = sec_gre_info.sec_spec.dike_info.tunnel_mode;
    
    if (tunnel_mode &&
        (sec_gre_info.gre_channel.state == AN_ACP_TUNN_CREATED_UP) &&
        sec_gre_info.gre_channel.ifhndl) {
       
         //dike cleanup
        an_dike_profile_remove_on_tunnel(sec_gre_info.gre_channel.ifhndl);
        an_syslog(AN_SYSLOG_ACP_DIKE_TO_NBR_REMOVED,
                  an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                  nbr_link_data)), nbr->udi.data,
                  an_if_get_name(nbr_link_data->local_ifhndl));
        
        // tunnel removal 
        an_acp_tunnel_unconfigure_and_delete(sec_gre_info.gre_channel.ifhndl);
        an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_REMOVED,
                  an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                  nbr_link_data)), nbr->udi.data,
                  an_if_get_name(nbr_link_data->local_ifhndl));
        
        an_event_acp_on_nbr_link_removed(nbr, nbr_link_data); 
        an_acp_init_acp_info_per_nbr_link(nbr_link_data);
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to remove %s secure channel to Nbr[%s] ",
                     an_bs_event, "AN_ACP_DIKE_ON_GRE", nbr->udi.data);
    }
    

    return;
}

static void 
an_acp_remove_nosec_on_gre_tunnel (an_nbr_t *nbr,
                                   an_nbr_link_spec_t *nbr_link_data)
{
    an_acp_nosec_on_gre_info_t nosec_gre_info;
    
    if (!nbr || !nbr_link_data) {
        return;
    }

    nosec_gre_info = nbr_link_data->acp_info.sec_channel_spec.nosec_gre_info;
    if ((nosec_gre_info.gre_channel.state == AN_ACP_TUNN_CREATED_UP) &&
        (nosec_gre_info.gre_channel.ifhndl)) {
        an_acp_tunnel_unconfigure_and_delete(nosec_gre_info.gre_channel.ifhndl);
        an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_REMOVED,
                  an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr, nbr_link_data)), 
                  nbr->udi.data, an_if_get_name(nbr_link_data->local_ifhndl));
        an_event_acp_on_nbr_link_removed(nbr, nbr_link_data);
        an_acp_init_acp_info_per_nbr_link(nbr_link_data);
    }
    return;
}

static void
an_acp_create_nosec_on_gre_tunnel (an_nbr_t *nbr,
                                   an_nbr_link_spec_t *nbr_link_data)
{
    an_addr_t addr_src = AN_ADDR_ZERO;
    an_if_t tunn_ifhndl = 0;

    if (!nbr || !nbr_link_data) {
        return;
    }

    an_addr_set_from_v6addr(&addr_src,
                            an_ipv6_get_ll(nbr_link_data->local_ifhndl));
    tunn_ifhndl = an_acp_tunnel_create_and_configure(addr_src,
                                                   nbr_link_data->ipaddr, 
                                                   nbr_link_data->local_ifhndl);
    if (tunn_ifhndl) {
        nbr_link_data->acp_info.sec_channel_established = AN_ACP_NOSEC_ON_GRE;
        nbr_link_data->acp_info.sec_channel_spec.nosec_gre_info.gre_channel.ifhndl = tunn_ifhndl;
        nbr_link_data->acp_info.sec_channel_spec.nosec_gre_info.gre_channel.state =
                                                         AN_ACP_TUNN_CREATED_UP;
        an_event_acp_on_nbr_link_created(nbr, nbr_link_data);

        an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_CREATED,
                  an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                  nbr_link_data)), nbr->udi.data,
                  an_if_get_name(nbr_link_data->local_ifhndl));
    } else {
        nbr_link_data->acp_info.sec_channel_spec.nosec_gre_info.gre_channel.state =
                                                         AN_ACP_TUNN_NONE;
        nbr_link_data->acp_info.sec_channel_established = AN_ACP_NONE;
        an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_FAILED,
                  an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                  nbr_link_data)), nbr->udi.data,
                  an_if_get_name(nbr_link_data->local_ifhndl));
    }
    return;
}

static void
an_acp_create_ipsec_on_gre_tunnel (an_nbr_t *nbr,
                                   an_nbr_link_spec_t *nbr_link_data)
{
    an_addr_t addr_src = AN_ADDR_ZERO;
    an_if_t tunn_ifhndl = 0;
    boolean ipsec_apply_on_tunn = FALSE;
    
    if (!nbr || !nbr_link_data) {
        return;
    }

    an_addr_set_from_v6addr(&addr_src,
                            an_ipv6_get_ll(nbr_link_data->local_ifhndl));
    tunn_ifhndl = an_acp_tunnel_create_and_configure(addr_src,
                            nbr_link_data->ipaddr, nbr_link_data->local_ifhndl);
    if (tunn_ifhndl) {
        nbr_link_data->acp_info.sec_channel_established = AN_ACP_IPSEC_ON_GRE;
        nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.ifhndl = tunn_ifhndl;
        an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_CREATED,
                  an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                  nbr_link_data)), nbr->udi.data,
                  an_if_get_name(nbr_link_data->local_ifhndl));
        
        ipsec_apply_on_tunn = an_ipsec_apply_on_tunnel(tunn_ifhndl, addr_src,
                            nbr_link_data->ipaddr, nbr_link_data->local_ifhndl);
        if (ipsec_apply_on_tunn && nbr_link_data->acp_info.sec_channel_established &&
            AN_CHECK_BIT_FLAGS(nbr_link_data->acp_info.sec_channel_negotiated,
                               nbr_link_data->acp_info.sec_channel_established)) {
            an_syslog(AN_SYSLOG_ACP_IPSEC_TO_NBR_CREATED,
                      an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                      nbr_link_data)), nbr->udi.data,
                      an_if_get_name(nbr_link_data->local_ifhndl));
            nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.sec_spec.ipsec_info.tunnel_mode = TRUE;
            nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.state =
                                                         AN_ACP_TUNN_CREATED_UP;
            an_event_acp_on_nbr_link_created(nbr, nbr_link_data);
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sCreated AN Control Plane secure "
                         "channel [%s] on %s to the nbr [%s]",
                         an_bs_event, "AN_ACP_IPSEC_ON_GRE",
                         an_if_get_name(nbr_link_data->local_ifhndl),
                         nbr->udi.data);
        } else {
            nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.state =
                                                         AN_ACP_TUNN_NONE;
            nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.sec_spec.ipsec_info.tunnel_mode = FALSE;
            nbr_link_data->acp_info.sec_channel_established = AN_ACP_NONE;

            an_syslog(AN_SYSLOG_ACP_IPSEC_TO_NBR_FAILED,
                      an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                      nbr_link_data)), nbr->udi.data,
                      an_if_get_name(nbr_link_data->local_ifhndl));
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sFailed to create AN Control Plane "
                         "secure channel [%s] on %s to the nbr [%s]",
                         an_bs_event, "AN_ACP_IPSEC_ON_GRE",
                         an_if_get_name(nbr_link_data->local_ifhndl),
                         nbr->udi.data);
            //delete the tunnel created if failed to apply ipsec on tunnel
            an_tunnel_remove(tunn_ifhndl);
            an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_REMOVED,
                      an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                      nbr_link_data)), nbr->udi.data,
                      an_if_get_name(nbr_link_data->local_ifhndl));
        }
    } else {
        an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_FAILED,
                  an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                  nbr_link_data)), nbr->udi.data,
                  an_if_get_name(nbr_link_data->local_ifhndl));
    }
}
        
static void
an_acp_create_dike_on_gre_tunnel (an_nbr_t *nbr,
                                   an_nbr_link_spec_t *nbr_link_data)
{
    an_addr_t addr_src = AN_ADDR_ZERO;
    an_if_t tunn_ifhndl = 0;
    boolean dike_apply_on_tunn = FALSE;
    
    if (!nbr || !nbr_link_data) {
        return;
    }

    an_addr_set_from_v6addr(&addr_src,
                            an_ipv6_get_ll(nbr_link_data->local_ifhndl));
    tunn_ifhndl = an_acp_tunnel_create_and_configure(addr_src,
                            nbr_link_data->ipaddr, nbr_link_data->local_ifhndl);
    if (tunn_ifhndl) {
        nbr_link_data->acp_info.sec_channel_established = AN_ACP_DIKE_ON_GRE;
        nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.ifhndl = tunn_ifhndl;
        an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_CREATED,
                  an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                  nbr_link_data)), nbr->udi.data,
                  an_if_get_name(nbr_link_data->local_ifhndl));
        
        dike_apply_on_tunn = an_dike_profile_apply_on_tunnel(tunn_ifhndl, 
                             AN_DIKE_LOCAL_PORT, AN_DIKE_REMOTE_PORT);
        if (dike_apply_on_tunn && nbr_link_data->acp_info.sec_channel_established &&
            AN_CHECK_BIT_FLAGS(nbr_link_data->acp_info.sec_channel_negotiated,
                               nbr_link_data->acp_info.sec_channel_established)) {
            an_syslog(AN_SYSLOG_ACP_DIKE_TO_NBR_CREATED,
                      an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                      nbr_link_data)), nbr->udi.data,
                      an_if_get_name(nbr_link_data->local_ifhndl));
            nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.sec_spec.dike_info.tunnel_mode = TRUE;
            nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.state =
                                                         AN_ACP_TUNN_CREATED_UP;
            an_event_acp_on_nbr_link_created(nbr, nbr_link_data);
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sCreated AN Control Plane secure "
                         "channel [%s] on %s to the nbr [%s]",
                         an_bs_event, "AN_ACP_DIKE_ON_GRE",
                         an_if_get_name(nbr_link_data->local_ifhndl),
                         nbr->udi.data);
        } else {
            nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.state =
                                                         AN_ACP_TUNN_NONE;
            nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.sec_spec.dike_info.tunnel_mode = FALSE;
            nbr_link_data->acp_info.sec_channel_established = AN_ACP_NONE;

            an_syslog(AN_SYSLOG_ACP_DIKE_TO_NBR_FAILED,
                      an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                      nbr_link_data)), nbr->udi.data,
                      an_if_get_name(nbr_link_data->local_ifhndl));
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sFailed to create AN Control Plane "
                         "secure channel [%s] on %s to the nbr [%s]",
                         an_bs_event, "AN_ACP_DIKE_ON_GRE",
                         an_if_get_name(nbr_link_data->local_ifhndl),
                         nbr->udi.data);
            //delete the tunnel created if failed to apply dike on tunnel
            an_tunnel_remove(tunn_ifhndl);
            an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_REMOVED,
                      an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                      nbr_link_data)), nbr->udi.data,
                      an_if_get_name(nbr_link_data->local_ifhndl));
        }
    } else {
        an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_FAILED,
                  an_if_get_name(an_acp_get_acp_if_on_nbr_link(nbr,
                  nbr_link_data)), nbr->udi.data,
                  an_if_get_name(nbr_link_data->local_ifhndl));
    }
}

void
an_acp_create_per_nbr_link (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{

    if (!nbr || !nbr_link_data) {
        return;
    }

    if (!an_acp_initialized) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAN Control Plane not initialized, hence failed to "
                     "create AN Control Plane to nbr [%s] on %s",
                     an_bs_event, nbr->udi.data,
                     an_if_get_name(nbr_link_data->local_ifhndl));
        return;
    }

    if (!nbr_link_data->acp_info.sec_channel_negotiated) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNegotiated AN Control Plane secure channel type with the "
                     "Nbr[%s] is NONE", an_bs_event, nbr->udi.data);
        return;
    }

    if (nbr_link_data->acp_info.sec_channel_established) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sAN Control Plane is already established to Nbr "
                    "[%s] on %s", an_bs_event, nbr->udi.data,
                    an_if_get_name(nbr_link_data->local_ifhndl));
        return;
    }

    if (an_ni_is_nbr_inside(nbr)) {
        switch (nbr_link_data->acp_info.sec_channel_negotiated) {
            case AN_ACP_IPSEC_ON_PHY:
                an_acp_routing_enable_on_interface(nbr_link_data->local_ifhndl,
                                                   an_get_routing_info());
                nbr_link_data->acp_info.sec_channel_established = AN_ACP_IPSEC_ON_PHY;
                nbr_link_data->acp_info.sec_channel_spec.sec_phy_info.phy_channel.ifhndl =
                                    nbr_link_data->local_ifhndl;
                an_event_acp_on_nbr_link_created(nbr, nbr_link_data);

                //Not possible to add ipsec security part on physical as 
                //it will apply for all the traffic 
                DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                             "\n%sCreated AN Control Plane [%s] on "
                             "%s to nbr [%s]", an_bs_event, "AN_ACP_IPSEC_ON_PHY",
                             an_if_get_name(nbr_link_data->local_ifhndl),
                             nbr->udi.data);
                break;
            case AN_ACP_NOSEC_ON_PHY:
                an_acp_routing_enable_on_interface(nbr_link_data->local_ifhndl,
                                                   an_get_routing_info());
                nbr_link_data->acp_info.sec_channel_established = AN_ACP_NOSEC_ON_PHY;
                nbr_link_data->acp_info.sec_channel_spec.nosec_phy_info.phy_channel.ifhndl =
                                    nbr_link_data->local_ifhndl;
                an_event_acp_on_nbr_link_created(nbr, nbr_link_data);
                break;

            case AN_ACP_IPSEC_ON_GRE:
                an_acp_create_ipsec_on_gre_tunnel(nbr, nbr_link_data);
                break;

            case AN_ACP_DIKE_ON_GRE:
                an_acp_create_dike_on_gre_tunnel(nbr, nbr_link_data);
                break;

            case AN_ACP_NOSEC_ON_GRE:
                an_acp_create_nosec_on_gre_tunnel(nbr, nbr_link_data);
                break;
            default:
                DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                             "\n%sNegotiated AN Control Plane channel to Nbr [%s] "
                              "is of unsupported type", an_bs_event, nbr->udi.data);
                break;
        }
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNbr [%s] not in the AN domain, hence failed to "
                     "create AN Control Plane to Nbr",
                     an_bs_event, nbr->udi.data);
    }
    return;
}

void
an_acp_init_acp_info_per_nbr_link (an_nbr_link_spec_t *nbr_link)
{
    if (!nbr_link) {
        return;
    }
    an_memset_s((uint8_t *)&nbr_link->acp_info, 0, sizeof(nbr_link->acp_info));
}

boolean
an_acp_remove_per_nbr_link (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    an_acp_nosec_on_phy_info_t nosec_phy_info;
    an_acp_sec_on_phy_info_t sec_phy_info;

    if (!nbr || !nbr_link_data) {
        return (FALSE);
    }

    if (!nbr_link_data->acp_info.sec_channel_established) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAN Control Plane channel not yet established to Nbr "
                     "[%s]", an_bs_event, nbr->udi.data);
        return (TRUE);
    }

    if (an_ni_is_nbr_inside(nbr)) {
        switch (nbr_link_data->acp_info.sec_channel_established) {
            case AN_ACP_IPSEC_ON_PHY:
                sec_phy_info =
                    nbr_link_data->acp_info.sec_channel_spec.sec_phy_info;
                an_acp_routing_disable_on_interface(sec_phy_info.phy_channel.ifhndl,
                                                    an_get_routing_info());
                an_event_acp_on_nbr_link_removed(nbr, nbr_link_data);
                an_acp_init_acp_info_per_nbr_link(nbr_link_data);
                return (TRUE);

            case AN_ACP_NOSEC_ON_PHY:
                nosec_phy_info =
                    nbr_link_data->acp_info.sec_channel_spec.nosec_phy_info;
                an_acp_routing_disable_on_interface(nosec_phy_info.phy_channel.ifhndl,
                                                    an_get_routing_info());
                an_event_acp_on_nbr_link_removed(nbr, nbr_link_data);
                an_acp_init_acp_info_per_nbr_link(nbr_link_data);
                return (TRUE);
    
            case AN_ACP_IPSEC_ON_GRE:
                 an_acp_remove_ipsec_on_gre_tunnel(nbr, nbr_link_data);
                 return (TRUE);

            case AN_ACP_DIKE_ON_GRE:
                 an_acp_remove_dike_on_gre_tunnel(nbr, nbr_link_data);
                 return (TRUE);

            case AN_ACP_NOSEC_ON_GRE:
                 an_acp_remove_nosec_on_gre_tunnel(nbr, nbr_link_data);
                 return (TRUE);

            default:
                break;
        }
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sNbr [%s] is not inside the AN domain, failed to remove"
                 "AN control plane on %s",
                 an_bs_event, nbr->udi.data,
                 an_if_get_name(nbr_link_data->local_ifhndl));
    return (FALSE);
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
            an_acp_negotiate_secure_channel_per_nbr_link(nbr, nbr_link_data);
        }
    }
   
    return TRUE;
}

static an_avl_walk_e
an_acp_create_nbrs_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    
    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }
    
    if (!an_ni_is_nbr_inside(nbr)) {
        return (AN_AVL_WALK_SUCCESS);
    }
   
    an_acp_create_to_nbr_for_all_valid_nbr_links(nbr);
    return (AN_AVL_WALK_SUCCESS);
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

static an_avl_walk_e
an_acp_remove_nbrs_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    
    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }

    an_acp_remove_to_nbr_for_all_valid_nbr_links(nbr);
    return (AN_AVL_WALK_SUCCESS);
}

static void 
an_acp_remove_for_all_valid_neighbors (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sRemove AN Control Plane for all bootstrapped nbrs " 
                 "walking the Nbr DB", an_bs_event);
    
    an_nbr_db_walk(an_acp_remove_nbrs_cb, NULL);
}

#if 0
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

static an_avl_walk_e 
an_acp_remove_ipsec_nbrs_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    
    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }
    
    an_acp_remove_ipsec_to_nbr_for_all_valid_nbr_links(nbr);
    return (AN_AVL_WALK_SUCCESS);
}

static void
an_acp_remove_ipsec_for_all_valid_neighbors (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sRemove ACP IPsec for all bootstrapped nbrs "
                 "walking the Nbr DB", an_bs_event);
    
    an_nbr_db_walk(an_acp_remove_ipsec_nbrs_cb, NULL);
}
#endif

void
an_acp_vrf_init (void)
{
    an_vrf_info_t *vrf_info = NULL;
    boolean an_vrf_created = FALSE;

    if (!an_acp_is_vrf_applicable()) {
        return;
    }
   
    an_vrf_set_name(AN_VRF_NUM_START);
    an_vrf_created = an_vrf_define();
    an_vrf_set_id();
    
    if (an_vrf_created) {
        vrf_info = an_vrf_get();
        if (vrf_info != NULL) {
            an_syslog(AN_SYSLOG_ACP_VRF_GLOBAL_CREATE_SUCCESS,
                  vrf_info->an_vrf_name, vrf_info->an_vrf_id);
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sCreated VRF, vrf_name [%s] and vrf_id %d",
                     an_bs_event, vrf_info->an_vrf_name, 
                     vrf_info->an_vrf_id);
        }
    } else {
        if (vrf_info != NULL) {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNot able to create AN VRF", an_bs_event);
            an_syslog(AN_SYSLOG_ACP_VRF_GLOBAL_CREATE_FAIL,
                  vrf_info->an_vrf_name, vrf_info->an_vrf_id);
        }
    }
}

void
an_acp_init (void)
{ 
    an_cerrno rc = EOK;
    an_routing_cfg_t routing_info;

    an_memset_s(&routing_info, 0, sizeof(routing_info));
    /* Make sure that the previous ACP instance is brought down first */
    an_acp_uninit();
    an_acp_cnp_init();

    rc = an_avl_init(&an_acp_client_tree, an_acp_client_compare);
    if (CERR_IS_NOTOK(rc)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%s AN ACP Client DB Init Failed", an_bs_event);
    }
    
    if (!an_set_secure_channel_cli) {
        an_acp_set_default_cap_set(AN_ACP_CNP_PARAM_SECURE_CHANNEL);
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sBringing up AN control plane globally", an_bs_event);

    /* Set up AN VRF */
    an_set_afi(AN_AF_IPv6);
    an_acp_vrf_init();

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
    
    /*NMS */
    an_acp_uninit_connection();
    
    //Cleanup to be done before ACP down
    an_event_acp_pre_uninitialization();

    /* Remove the secure channel */
    an_acp_remove_for_all_valid_neighbors();

    /*Remove IPSec profile and then remove IKev2*/
    an_ipsec_profile_uninit();
    an_ipsec_clear_profile_name();
    
    /*Remove IKev2 profile*/
    an_ikev2_profile_uninit();
    an_ikev2_clear_profile_names();

    an_unconfig_loopback();
   
    an_ipv6_unicast_routing_enable_disable_unregister();
    an_acp_routing_disable(routing_info);
    an_acp_routing_uninit();
    
    an_vrf_remove();

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

    /*NMS */
    an_acp_uninit_connection();
   
    an_avl_uninit(&an_acp_client_tree);
    an_acp_cnp_uninit();
    an_acp_initialized = FALSE;
    
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
    an_list_t *list_of_ipv6_addresses = NULL;    
    an_v4addr_t v4addr = AN_V4ADDR_ZERO;   
    an_v4addr_t v4mask = AN_V4ADDR_ZERO; 
    an_vrf_info_t *vrf_info = NULL;

    vrf_info = an_vrf_get();
    if (!ifhndl) {
        return (FALSE);
    }
  
    if (!an_if_check_type_layer3(ifhndl)) {
        return (FALSE);
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

    /* Uninitialize configurations on the interface */

    /* Save the list of ipv6 addresses configured on the interface,
     * before changing state from HOLD to ACTIVE. This is because
     * when autonomic connect is issued, the interface is put into
     * AN's vrf and that in turn results in removing of all ip addresses
     * on the interface. Hence, we are restoring those addresses back after
     * vrf config is done.
     */

    v4addr = an_addr_get_v4addr_from_interface(ifhndl);
    v4mask = an_addr_get_v4mask_from_interface(ifhndl);
    list_of_ipv6_addresses = 
                        an_ipv6_get_list_of_ipv6_addresses_on_interface(ifhndl);

    /* Initialize configurations to make the interface external connection ready */    
    if (an_acp_is_vrf_applicable()) {
        if (!an_vrf_configure_interface(ifhndl)) {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sFailed to set up vrf on the interface [%s]", 
                         an_bs_event, an_if_get_name(ifhndl));
            an_syslog(AN_SYSLOG_ACP_VRF_INTERFACE_CREATE_FAIL, 
                      an_if_get_name(ifhndl), vrf_info->an_vrf_name, 
                      vrf_info->an_vrf_id);
            if (list_of_ipv6_addresses) {
                an_ipv6_set_and_clean_v6addr_on_interface_and_nvgen(list_of_ipv6_addresses,
                                                                                   ifhndl);
            } 
            if (v4addr && v4mask) {
                an_addr_set_v4addr_on_interface_and_nvgen(ifhndl, v4addr, v4mask);
            }
            return (FALSE);
        }
    }

    an_nd_set_preference(ifhndl, AN_ND_CLIENT_CONNECT, AN_ND_CFG_DISABLED);
    an_nd_startorstop(ifhndl);

    if (!an_ipv6_enable_on_interface(ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to enable IPv6 on the interface [%s]",
                     an_bs_event, an_if_get_name(ifhndl));
        if (list_of_ipv6_addresses) {
            an_ipv6_set_and_clean_v6addr_on_interface_and_nvgen(list_of_ipv6_addresses,
                                                                               ifhndl);
        }
        if (v4addr && v4mask) {
            an_addr_set_v4addr_on_interface_and_nvgen(ifhndl, v4addr, v4mask);
        }
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
    an_sd_cfg_if_commands(ifhndl, TRUE);
    an_discover_services(ifhndl);
   
    /* Reapply the saved ipv4 and ipv6 addresses which were configured by user
    */
    if (list_of_ipv6_addresses) {
        an_ipv6_set_and_clean_v6addr_on_interface_and_nvgen(list_of_ipv6_addresses,
                                                                                ifhndl);    
    }
    if (v4addr && v4mask) {
        an_addr_set_v4addr_on_interface_and_nvgen(ifhndl, v4addr, v4mask);    
    }

    return (TRUE);
}

boolean
an_acp_hold_external_connection (an_if_t ifhndl)
{
    an_routing_cfg_t routing_info;
    uint8_t *sudi_keypair_label = NULL;   
    
    if (!an_if_check_type_layer3(ifhndl)) {
        return FALSE;
    }

    /* Unitialize configurations on the interface */
    an_nd_set_preference(ifhndl, AN_ND_CLIENT_CONNECT, AN_ND_CFG_DEFAULT);
    an_nd_startorstop(ifhndl);

    /*an_ipv6_send_change_nd_mode(ifhndl, IPV6_SEND_SECMODE_FULL_SECURE);*/
    if (an_acp_is_vrf_applicable()) {
        if (!an_vrf_unconfigure_interface(ifhndl)) {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sFailed to unconfigure vrf from interface %s",
                         an_bs_event, an_if_get_name(ifhndl));
            return (FALSE);
        }
    }

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
    an_sd_cfg_if_commands(ifhndl, FALSE);

    return (TRUE);
}

boolean
an_acp_uninit_external_connection (an_if_t ifhndl)
{
    an_routing_cfg_t routing_info;
    uint8_t *sudi_keypair_label = NULL;
    an_list_t *list_of_ipv6_addresses = NULL;
    an_v4addr_t v4addr = AN_V4ADDR_ZERO;
    an_v4addr_t v4mask = AN_V4ADDR_ZERO;
 
    if (!ifhndl) {
        return (FALSE);
    }

    if (!an_if_check_type_layer3(ifhndl)) {
        return FALSE;
    }
    
    /* Save the manually configured ipv4 address and list of ipv6 addresses
     * configured on the interface as these would be removed by AN with the
     * "no autonomic connect" command. Reapply them at a later stage in this
     * function
     */
    v4addr = an_addr_get_v4addr_from_interface(ifhndl);
    v4mask = an_addr_get_v4mask_from_interface(ifhndl);
    list_of_ipv6_addresses =
                         an_ipv6_get_list_of_ipv6_addresses_on_interface(ifhndl);
    

    /*an_ipv6_send_change_nd_mode(ifhndl, IPV6_SEND_SECMODE_FULL_SECURE);*/
    if (an_acp_is_vrf_applicable()) {

        if (!an_vrf_unconfigure_interface(ifhndl)) {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sFailed to unconfigure vrf from interface %s",
                         an_bs_event, an_if_get_name(ifhndl));
            if (list_of_ipv6_addresses) {
                an_ipv6_set_and_clean_v6addr_on_interface_and_nvgen(list_of_ipv6_addresses,
                                                                                   ifhndl);
            }
            if (v4addr && v4mask) {
                an_addr_set_v4addr_on_interface_and_nvgen(ifhndl, v4addr, v4mask);
            }
            return (FALSE);
        }
    }

    /* Unitialize configurations on the interface */   
    an_nd_set_preference(ifhndl, AN_ND_CLIENT_CONNECT, AN_ND_CFG_DEFAULT);
    an_nd_startorstop(ifhndl);

    if (!an_ipv6_enable_on_interface(ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to enable ipv6 on interface %s", an_bs_event,
                     an_if_get_name(ifhndl));
        if (list_of_ipv6_addresses) {
            an_ipv6_set_and_clean_v6addr_on_interface_and_nvgen(list_of_ipv6_addresses,
                                                                               ifhndl);
        }
        if (v4addr && v4mask) {
            an_addr_set_v4addr_on_interface_and_nvgen(ifhndl, v4addr, v4mask);
        }
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
    an_sd_cfg_if_commands(ifhndl, FALSE);

    /* Reapply the saved ipv4 and ipv6 addresses which were configured by user
     */
    if (list_of_ipv6_addresses) {
        an_ipv6_set_and_clean_v6addr_on_interface_and_nvgen(list_of_ipv6_addresses,
                                                                                ifhndl);
    }
    if (v4addr && v4mask) {
        an_addr_set_v4addr_on_interface_and_nvgen(ifhndl, v4addr, v4mask);
    }
    an_discover_services_stop(ifhndl);

    return (TRUE);
}

static an_avl_walk_e
an_acp_init_connection_device_bootstrapped_cb (an_avl_node_t *node, void *data)
{
    an_if_info_t *an_if_info = NULL;

    if (!node) {
        return (AN_AVL_WALK_FAIL);
    }
    an_if_info = (an_if_info_t *)node;

    if (an_if_info->an_if_acp_info.ext_conn_state == AN_EXT_CONNECT_STATE_HOLD) {
        an_acp_init_external_connection(an_if_info->ifhndl);
    }

    return (AN_AVL_WALK_SUCCESS);
}

void
an_acp_init_connection_device_bootstrapped (void)
{
    an_if_info_db_walk(an_acp_init_connection_device_bootstrapped_cb, NULL);
}

an_avl_walk_e
an_acp_uninit_connection_cb (an_avl_node_t *node, void *data)
{
    an_if_info_t *an_if_info = NULL;

    if (!node) {
        return (AN_AVL_WALK_FAIL);
    }
    an_if_info = (an_if_info_t *)node;

    if (an_if_info->an_if_acp_info.ext_conn_state == AN_EXT_CONNECT_STATE_DONE) {
        an_acp_hold_external_connection(an_if_info->ifhndl);
    }

    return (AN_AVL_WALK_SUCCESS);
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
    if (nbr_link_data->acp_info.sec_channel_established != AN_ACP_NONE) {
       return (TRUE);
    } else {
        return (FALSE);
    }
}

boolean 
an_acp_is_up_on_nbr (an_nbr_t *nbr)
{
   an_list_element_t *elem = NULL;
   an_nbr_link_spec_t *nbr_link_data = NULL;
                       
   AN_FOR_ALL_DATA_IN_LIST(nbr->an_nbr_link_list, elem, nbr_link_data) {
      if (nbr_link_data->acp_info.sec_channel_established != AN_ACP_NONE) {
          return (TRUE);
      }
   }
   return FALSE;
}

void
an_acp_nbr_link_add_event_handler (void *link_info)
{
    an_event_nbr_link_add_lost_info_t *nbr_link_info = NULL;
    an_nbr_t *nbr = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;

    if(!link_info) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid link info to handle nbr link add event ");
        return;
    }
    nbr_link_info = (an_event_nbr_link_add_lost_info_t *)link_info;
    nbr = nbr_link_info->nbr;
    nbr_link_data = nbr_link_info->nbr_link_data;

    if (!nbr || !nbr_link_data) {
       return;
    }
    if (!an_acp_is_up_on_nbr_link(nbr_link_data)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sInitiaing ACP channel negotiation on the "
                     "fresh Nbr[%s] link [%s]", an_nd_event, nbr->udi.data,
                     an_if_get_name(nbr_link_data->local_ifhndl));
        an_acp_negotiate_secure_channel_per_nbr_link(nbr, nbr_link_data);
    }

    return;
}

void
an_acp_domain_device_cert_expired_event_handler (void *info_ptr)
{
    an_udi_t my_udi = {0};

    if (!an_get_udi(&my_udi))  {
        return;
    }

    //TBD: Stop services before bring down ACP    
    //Stop config download, service discovery, aaa

    /* Reset ACP */
    an_acp_uninit();

    /*Clear dbs*/
    an_acp_client_db_init();
}

void
an_acp_nbr_link_cleanup (an_nbr_link_context_t *nbr_link_ctx)
{
    an_nbr_t *nbr = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;

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
    an_syslog(AN_SYSLOG_NBR_LOST,
                  nbr->udi.data, an_if_get_name(nbr_link_data->local_ifhndl));

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sNbr[%s] Link [%s] Lost", an_nd_event, nbr->udi.data,
                 an_if_get_name(nbr_link_data->local_ifhndl));

    an_acp_ntp_nbr_link_cleanup(nbr_link_data);
    
    if (an_acp_is_up_on_nbr_link(nbr_link_data)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sRemoving AN Control Plane on the Nbr[%s] link [%s]",
                     an_nd_event, nbr->udi.data,
                     an_if_get_name(nbr_link_data->local_ifhndl));
        an_acp_remove_per_nbr_link(nbr, nbr_link_data);
    }
}

void
an_acp_nbr_inside_domain_event_handler (void *nbr_info)
{
    an_cert_t domain_cert = {};
    an_if_t nbr_ifhndl = 0;
    an_nbr_t *nbr = NULL;

    if(!nbr_info) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle nbr inside domain event ");
        return;
    }
    nbr = (an_nbr_t *)nbr_info;
    if (!nbr || !nbr->device_id || !nbr->domain_id) {
        return;
    }

    if (!an_nbr_get_addr_and_ifs(nbr, NULL, &nbr_ifhndl, NULL)) {
        return;
    }       
     
    an_get_domain_cert(&domain_cert);
    
    if (domain_cert.len && domain_cert.data) {
        an_acp_create_to_nbr_for_all_valid_nbr_links(nbr);
    }

}

void
an_acp_nbr_outside_domain_event_handler (void *nbr_info)
{
    an_nbr_t *nbr = NULL;

    if(!nbr_info) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle nbr outside domain event ");
        return;
    }
    nbr = (an_nbr_t *)nbr_info;

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
              "\n%sNbr [%s] is out of domain", an_nd_event, nbr->udi.data);

    if (an_acp_is_up_on_nbr(nbr)) {
        an_acp_remove_to_nbr_for_all_valid_nbr_links(nbr);
    }
}

void
an_acp_anr_up_locally_event_handler (void *info_ptr)
{
    an_acp_ntp_anr_locally_up_event();
}

void
an_acp_anr_shut_event_handler (void *info_ptr)
{
    an_acp_ntp_anr_shut_event();
}

void
an_acp_nbr_cert_validity_expired_event_handler (void *nbr_info)
{
    an_nbr_t *nbr = NULL;

    if(!nbr_info) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle nbr add event ");
        return;
    }
    nbr = (an_nbr_t *)nbr_info;
    an_acp_ntp_start_clock_sync_nbr(nbr);
}

void
an_acp_pre_uninit_event_handler (void *info_ptr)
{
    /*Syslog*/
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sSyslog uninitialized", an_bs_event);
    an_syslog_disconnect();
    return;
}

void
an_acp_init_event_handler (void *info_ptr)
{
    an_syslog_connect();
}

void
an_acp_if_autonomic_init_event_handler (void *if_info)
{
    an_if_info_t *an_if_info = NULL;
    an_if_t *ifhndl_info, ifhndl;

    if(!if_info) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle interface autonomic init event ");
        return;
    }
    ifhndl_info = (an_if_t *)if_info;
    ifhndl = *ifhndl_info;

    an_if_info = an_if_info_db_search(ifhndl, FALSE); 
    if (!an_if_info) {
       return;
    }

    if (an_if_info->an_if_acp_info.ext_conn_state ==
                AN_EXT_CONNECT_STATE_HOLD) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sACP Init external connection", an_bs_event);
        an_acp_init_external_connection(ifhndl);
    }
}

void
an_acp_if_autonomic_uninit_event_handler (void *if_info)
{
    an_if_info_t *an_if_info = NULL;
    an_if_t *ifhndl_info, ifhndl;

    if(!if_info) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle interface autonomic init event ");
        return;
    }
    ifhndl_info = (an_if_t *)if_info;
    ifhndl = *ifhndl_info;

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
       return;
    }

    if (an_if_info->an_if_acp_info.ext_conn_state ==
                AN_EXT_CONNECT_STATE_DONE) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sACP hold external connection", an_bs_event);
        an_acp_hold_external_connection(ifhndl);
    }
}

void
an_acp_removed_on_link_event_handler (void *link_info)
{
    an_nbr_t *nbr = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    an_nbr_link_context_t *nbr_link_ctx = NULL;

    if (!link_info) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr link info is NULL, Cant handle acp link"
               " removal event", an_bs_event);
        return;
    }

    nbr_link_ctx = (an_nbr_link_context_t *)link_info;

    if (nbr_link_ctx == NULL)
    {
       DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sContext is NULL in acp on link removed event", an_nd_event);
       return;
    }

    nbr = nbr_link_ctx->nbr;
    nbr_link_data = nbr_link_ctx->nbr_link_data;

    if (!nbr || !nbr_link_data) {
        return;
    }
    an_acp_remove_clock_sync_with_nbr(nbr);
}

void
an_acp_created_on_link_event_handler (void *link_info)
{
    an_nbr_t *nbr = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    an_nbr_link_context_t *nbr_link_ctx = NULL;

    if (!link_info) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr link info is NULL, Cant handle acp"
               " link create event", an_bs_event);
        return;
    }

    nbr_link_ctx = (an_nbr_link_context_t *)link_info;
    if (nbr_link_ctx == NULL)
    {
       DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sContext is NULL in acp on"
                    " link created event", an_nd_event);
       return;
    }

    nbr = nbr_link_ctx->nbr;
    nbr_link_data = nbr_link_ctx->nbr_link_data;

    if (!nbr || !nbr_link_data) {
        return;
    }
    an_acp_enable_clock_sync_with_nbr(nbr);
    an_acp_ntp_peer_remove_global(nbr);
}

void
an_acp_nbr_refreshed_event_handler (void *link_info)
{
    an_nbr_t *nbr = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    an_if_t tunn_ifhndl;
    an_if_t tunn_src_ifhndl;
    an_nbr_link_context_t *nbr_link_ctx = NULL;

    if (!link_info) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr link info is NULL, Cant handle nbr" 
               " refreshed event", an_bs_event);
        return;
    }

    nbr_link_ctx = (an_nbr_link_context_t *)link_info;
    if (nbr_link_ctx == NULL)
    {
       DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sContext is NULL in nbr_refreshed event", an_nd_event);
       return;
    }

    nbr = nbr_link_ctx->nbr;
    nbr_link_data = nbr_link_ctx->nbr_link_data;
    if (!nbr || !nbr->udi.data || !nbr_link_data) {
        return;
    }

    switch (nbr_link_data->acp_info.sec_channel_established) {
        case AN_ACP_IPSEC_ON_GRE:
            tunn_ifhndl =
                nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.ifhndl;
            tunn_src_ifhndl = nbr_link_data->local_ifhndl;
            an_tunnel_check_integrity(tunn_ifhndl, tunn_src_ifhndl);
            break;
        case AN_ACP_DIKE_ON_GRE:
            tunn_ifhndl =
                nbr_link_data->acp_info.sec_channel_spec.sec_gre_info.gre_channel.ifhndl;
            tunn_src_ifhndl = nbr_link_data->local_ifhndl;
            an_tunnel_check_integrity(tunn_ifhndl, tunn_src_ifhndl);
            break;
        case AN_ACP_NOSEC_ON_GRE:
            tunn_ifhndl =
                nbr_link_data->acp_info.sec_channel_spec.nosec_gre_info.gre_channel.ifhndl;
            tunn_src_ifhndl = nbr_link_data->local_ifhndl;
            an_tunnel_check_integrity(tunn_ifhndl, tunn_src_ifhndl);
            break;
        default:
            break;

     }

    if (nbr_link_data->acp_info.acp_secure_channel_negotiation_started &&
        an_unix_time_is_elapsed(nbr_link_data->acp_info.acp_secure_channel_negotiation_started,
                                AN_UNIX_TIME_ACP_RETRY_SECONDS)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                     "\n%sACP Secure Channel negotiation with %s on %s is not "
                     "complete in %d seconds, retyring it", an_bs_event,
                     nbr->udi.data, an_if_get_name(nbr_link_data->local_ifhndl),
                     AN_UNIX_TIME_ACP_RETRY_SECONDS);
        an_acp_negotiate_secure_channel_per_nbr_link(nbr, nbr_link_data);
    }
}

void
an_acp_device_bootstrap_event_handler (void *info_ptr)
{
     an_acp_init();
}

/*----------------AN ACP register for event handlers -------------------------*/

void
an_acp_register_for_events (void) 
{
    an_event_register_consumer(AN_MODULE_ACP, AN_EVENT_NBR_LINK_ADD,
                                     an_acp_nbr_link_add_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_DOMAIN_DEVICE_CERT_EXPIRED, 
                        an_acp_domain_device_cert_expired_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_NBR_INSIDE_DOMAIN, 
                        an_acp_nbr_inside_domain_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_NBR_OUTSIDE_DOMAIN, 
                        an_acp_nbr_outside_domain_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_ANR_UP_LOCALLY, 
                        an_acp_anr_up_locally_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_ANR_SHUT, an_acp_anr_shut_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_NBR_CERT_VALIDITY_EXPIRED, 
                        an_acp_nbr_cert_validity_expired_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_ACP_PRE_UNINIT, 
                        an_acp_pre_uninit_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_ACP_INIT, an_acp_init_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_INTF_AUTONOMIC_ENABLE, 
                        an_acp_if_autonomic_init_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_INTF_AUTONOMIC_DISABLE, 
                        an_acp_if_autonomic_uninit_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_ACP_ON_LINK_REMOVED, 
                        an_acp_removed_on_link_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_ACP_ON_LINK_CREATED, 
                        an_acp_created_on_link_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_NBR_REFRESHED, 
                        an_acp_nbr_refreshed_event_handler);
    an_event_register_consumer(AN_MODULE_ACP,
                        AN_EVENT_DEVICE_BOOTSTRAP, 
                        an_acp_device_bootstrap_event_handler);
}

