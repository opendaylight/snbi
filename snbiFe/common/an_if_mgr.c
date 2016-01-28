/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "an_if_mgr.h"
#include "an_anra.h"
#include "../al/an_misc.h"
#include "../al/an_mem.h"
#include "../al/an_if.h"
#include "../al/an_timer.h"
#include "an_event_mgr.h"

an_avl_tree  an_if_info_tree;  
an_if_info_t* an_if_info_database = NULL;
static an_mem_chunkpool_t *an_if_info_pool = NULL;
static const uint16_t AN_IF_INFO_POOL_SIZE = 64;
static boolean an_if_initialized = FALSE;
//an_avl_compare_e an_cd_info_compare_vlan(an_avl_node_t *node1, an_avl_node_t *node2);
//an_avl_compare_e an_cd_info_compare(an_avl_node_t *node1, an_avl_node_t *node2);

#define AN_TIMER_IF_BRING_UP_INTERVAL (10*1*1000)
#define AN_TIMER_IF_BRING_UP_RETRY 3

an_timer an_if_bring_up_timer;

an_if_info_t* 
an_if_info_alloc (void)
{
    an_if_info_t *an_if_info = NULL;

    if (!an_if_info_pool) {
        /* Allocate AN IF Info chunk pool */
        an_if_info_pool = an_mem_chunkpool_create(sizeof(an_if_info_t),
                              AN_IF_INFO_POOL_SIZE, "AN IF Info ChunkPool");
    }

    /* Try to allocate a AN IF Info */
    an_if_info = an_mem_chunk_malloc(an_if_info_pool);
    if (!an_if_info) {
        if (an_mem_chunkpool_destroyable(an_if_info_pool)) {
            an_mem_chunkpool_destroy(an_if_info_pool);
            an_if_info_pool = NULL;
        }
        return (NULL);
    }

    return (an_if_info);
} 

void
an_if_info_free (an_if_info_t *an_if_info)
{
    if (!an_if_info) {
        return;
    }

    an_mem_chunk_free(&an_if_info_pool, an_if_info);
}

an_avl_compare_e 
an_if_info_compare (an_avl_node_t *node1, an_avl_node_t *node2)
{
    an_if_info_t *an_if_info1 = (an_if_info_t *)node1;
    an_if_info_t *an_if_info2 = (an_if_info_t *)node2;

    if (!an_if_info1 && !an_if_info2) {
        return (AN_AVL_COMPARE_EQ);
    } else if (!an_if_info1) {
        return (AN_AVL_COMPARE_LT);
    } else if (!an_if_info2) {
        return (AN_AVL_COMPARE_GT);
    }

    if (an_if_info1->ifhndl < an_if_info2->ifhndl) {
        return (AN_AVL_COMPARE_LT);
    } else if (an_if_info1->ifhndl > an_if_info2->ifhndl) {
        return (AN_AVL_COMPARE_GT);
    } else { 
        return (AN_AVL_COMPARE_EQ);
    }
}

boolean
an_if_info_db_insert (an_if_info_t *an_if_info)
{
    if (!an_if_info) {
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sInserting interface (%s) to IF Info DB", 
                 an_nd_db, an_if_get_name(an_if_info->ifhndl));

    an_avl_insert_node((an_avl_top_p *)&an_if_info_database,
                  (an_avl_node_t *)an_if_info, an_if_info_compare,
                  &an_if_info_tree); 

    return (TRUE);
}

boolean
an_if_info_db_remove (an_if_info_t *an_if_info)
{
    if (!an_if_info) {
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sRemoving interface (%s)/%d from IF Info DB", 
                 an_nd_db, an_if_get_name(an_if_info->ifhndl),
                 an_if_info->ifhndl);
    an_avl_remove_node((an_avl_top_p *)&an_if_info_database,
                  (an_avl_node_t *)an_if_info, an_if_info_compare,
                  &an_if_info_tree); 

    return (TRUE);
}

void
an_if_set_nd_client_db_init (an_if_info_t *an_if_info)
{
    uint16_t nd_client;

    if(!an_if_info) {
        return;
    }
    
    for (nd_client = AN_ND_CLIENT_CLI; nd_client <  AN_ND_CLIENT_MAX; nd_client++) {
        an_if_info->an_nd_client_db[nd_client].an_nd_client_id = nd_client;
        an_if_info->an_nd_client_db[nd_client].an_nd_state = AN_ND_CFG_DEFAULT;
    }

    return;
}

an_if_info_t *
an_if_info_db_search (an_if_t ifhndl, boolean force)
{
    an_if_info_t goal_an_if_info = {}; 
    an_if_info_t *an_if_info = NULL;
    an_avl_node_t *avl_type = (an_avl_node_t *)&goal_an_if_info;
    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_INFO, NULL, 
                 "\n%sSearching interface (%s) in IF Info DB", 
                 an_nd_db, an_if_get_name(ifhndl));
    goal_an_if_info.ifhndl = ifhndl;
    an_if_info = (an_if_info_t *)
          an_avl_search_node((an_avl_top_p)an_if_info_database,
                             avl_type, an_if_info_compare, &an_if_info_tree); 

    if (!an_if_info && force) {
        
        if (!an_l2_check_intf_is_autonomic_possible(ifhndl)) {
            return (NULL);
        }
        an_if_info = an_if_info_alloc();
        if (!an_if_info) {
            return (NULL);
        }
        an_if_info->ifhndl = ifhndl;
        an_if_set_nd_client_db_init(an_if_info);
        an_if_info->nd_state = AN_ND_CFG_DEFAULT;

        an_if_info->nd_oper = AN_ND_OPER_DOWN;
        an_if_info->an_if_acp_info.ext_conn_state = AN_EXT_CONNECT_STATE_NO;
        an_if_info->if_cfg_autonomic_enable = TRUE;

        an_if_info->efp_id        = AN_SERVICE_INSTANCE_START;
        an_if_info->phy_ifhndl    = 0;
        an_if_info->vlan_ifhndl   = 0;
        an_if_info->tunnel_ifhndl = 0;
        /*
         * an_if_info is attached to all the interfaces in the box
         * only a few are created by the autonomic process.
         */
        an_if_info->autonomically_created = FALSE;

        an_if_info->an_if_sd_info.an_syslog_sdRef = 0;
        an_if_info->an_if_sd_info.an_aaa_sdRef = 0;
        an_if_info->an_if_sd_info.an_config_sdRef = 0;
        an_if_info->an_if_sd_info.an_anr_sdRef = 0;

        an_if_info_db_insert(an_if_info);
	an_cd_init_cd_if_info(an_if_info->ifhndl);
    }
    return (an_if_info);
}

void
an_if_info_db_walk (an_avl_walk_f walk_func, void *args)
{
    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sWalk IF Info DB", an_nd_db);
    an_avl_walk_all_nodes((an_avl_top_p *)&an_if_info_database, walk_func, 
                          an_if_info_compare, args, &an_if_info_tree);    
}

an_avl_walk_e
an_if_info_db_init_cb (an_avl_node_t *node, void *args)
{
    an_if_info_t *an_if_info = (an_if_info_t *)node;

    if (!an_if_info) {
        return (AN_AVL_WALK_FAIL);
    }

    an_if_info_db_remove(an_if_info);
    an_if_info_free(an_if_info);

    return (AN_AVL_WALK_SUCCESS);
}

void
an_if_info_db_init (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sInit IF Info DB", an_nd_db);
    an_if_info_db_walk(an_if_info_db_init_cb, NULL);
}

boolean
an_if_is_autonomically_created (an_if_info_t *an_if_info)
{
    if (!an_if_info) {
        return (FALSE);
    }

    return (an_if_info->autonomically_created);
}

void
an_if_set_cfg_autonomic_enable (an_if_info_t *an_if_info, boolean flag)
{
    if (!an_if_info) {
        return;
    }
    an_if_info->if_cfg_autonomic_enable = flag;
}

boolean
an_if_is_cfg_autonomic_enabled (an_if_info_t *an_if_info)
{
    if (!an_if_info)
        return (FALSE);
    else
        return (an_if_info->if_cfg_autonomic_enable);
}

boolean
an_if_is_autonomic_loopback (an_if_t loopbk_ifhndl) 
{
    an_if_info_t *loopback_if_info = NULL;

    if (!loopbk_ifhndl) {
        return (FALSE);
    }

    if (!an_if_is_loopback(loopbk_ifhndl)) {
        return (FALSE);
    }

    loopback_if_info = an_if_info_db_search(loopbk_ifhndl, FALSE);
    if (!an_if_is_autonomically_created(loopback_if_info)) {
        return (FALSE);
    }

    return (TRUE);
}

boolean
an_if_is_autonomic_tunnel (an_if_t tunn_ifhndl)
{
    an_if_info_t *tunnel_if_info = NULL;

    if (!tunn_ifhndl) {
        return (FALSE);
    }
    
    if (!an_if_is_tunnel(tunn_ifhndl)) {
        return (FALSE);
    }

    tunnel_if_info = an_if_info_db_search(tunn_ifhndl, FALSE);
    if (!an_if_is_autonomically_created(tunnel_if_info)) {
        return (FALSE);
    }
    return (TRUE);
}

boolean
an_should_bring_up_interfaces (void)
{
    if (!an_is_startup_config_exists()) {
        /* There is no startup-config, hence go ahead and bringup interfaces
         */
        return (TRUE);
    }

    return (FALSE);
}

boolean 
an_if_noshut_cb (an_if_t ifhndl, void *data)
{
    if (!ifhndl) {
        return (FALSE);
    }

    if (an_if_is_ethernet(ifhndl)) {
        an_if_bring_up(ifhndl);
        /*
         * Create an_if_info all interfaces.
         */ 
        an_if_info_db_search(ifhndl, TRUE); 
    }

    return (TRUE);
}

static boolean 
an_if_is_initialized (void)
{
    return (an_if_initialized);
}

boolean
an_if_info_create_cb (an_if_t ifhndl, void *data)
{
    an_if_info_db_search(ifhndl, TRUE);
    
    return (TRUE);
}

void 
an_if_init (void)
{
    if (an_if_is_initialized()) {
        return;
    }

    /* Creata an_if_info for all the interfaces first */
    an_if_walk(an_if_info_create_cb, NULL);

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sBringing UP all the interfaces", an_nd_event);
    an_if_initialized = TRUE;

}

void 
an_if_uninit (void)
{
    if (!an_if_is_initialized()) {
        return;
    }

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sStop timer to bring up all interfaces", an_nd_event);

    an_avl_uninit(&an_if_info_tree);
    an_if_initialized = FALSE;
}

void
an_if_autonomic_enable (an_if_t ifhndl)
{
    an_if_info_t *an_if_info = NULL;

    an_if_info = an_if_info_db_search(ifhndl, FALSE); 
    if (!an_if_info) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sCant execute Autonomic interface enable, input IF NULL", 
                 an_nd_event);
       return;
    }
    an_event_if_autonomic_enable(ifhndl);
}

void
an_if_autonomic_disable (an_if_t ifhndl)
{
    an_if_info_t *an_if_info = NULL;

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sCant execute Autonomic interface disable, input IF NULL", 
                 an_nd_event);
       return;
    }
    an_event_if_autonomic_disable(ifhndl);
}

boolean
an_if_check_routing_required (an_if_info_t *an_if_info)
{
    if (!an_if_info) {
        return FALSE;
    }

    if(an_if_info->an_if_acp_info.is_routing_required == TRUE) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

boolean
an_if_set_routing_required (an_if_info_t *an_if_info)
{
    if (!an_if_info) {
        return FALSE;
    }

    an_if_info->an_if_acp_info.is_routing_required = TRUE;
    return TRUE;
}


boolean
an_if_unset_routing_required (an_if_info_t *an_if_info)
{
    if (!an_if_info) {
        return FALSE;
    }

    an_if_info->an_if_acp_info.is_routing_required = FALSE;
    return TRUE;
}
                
void
an_if_interface_erased_event_handler (void *if_info_ptr)
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

    an_if_info_db_remove(an_if_info);
    an_if_info_free(an_if_info);
}

void
an_if_sudi_available_event_handler (void *info_ptr)
{
    an_if_init();
}

void
an_if_udi_available_event_handler (void *info_ptr)
{
    an_udi_t my_udi = {};

    if (!an_get_udi(&my_udi)) {
        return;
    }
    an_if_init();
}

/*-----------------AN INTF MGR register for event handlers -------------------*/
void
an_if_mgr_register_for_events (void) 
{
    an_event_register_consumer(AN_MODULE_INTF_MGR,
                        AN_EVENT_INTERFACE_ERASED, 
                        an_if_interface_erased_event_handler);
    an_event_register_consumer(AN_MODULE_INTF_MGR,
                        AN_EVENT_SUDI_AVAILABLE, 
                        an_if_sudi_available_event_handler);
    an_event_register_consumer(AN_MODULE_INTF_MGR,
                        AN_EVENT_UDI_AVAILABLE, 
                        an_if_udi_available_event_handler);
}

 
