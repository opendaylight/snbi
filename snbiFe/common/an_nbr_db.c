/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "an_nbr_db.h"
#include "an_event_mgr.h"
#include "../al/an_timer.h"
#include "../al/an_addr.h"
#include "../al/an_avl.h"
#include "../al/an_mem.h"
#include "../al/an_logger.h"
#include "../al/an_str.h"
#include "../al/an_if.h"
//#include "an_topo_disc.h"
#include "an_nd.h"
#include "an_acp.h"

an_avl_tree an_nbr_tree;
an_nbr_t* an_nbr_database = NULL;
static an_mem_chunkpool_t *an_nbr_pool = NULL;
static const uint16_t AN_NBR_POOL_SIZE = 64;

static void
an_nbr_alloc_init (an_nbr_t *nbr)
{
    int32_t index = 0;
    
    an_timer_init(&nbr->cert_request_timer, AN_TIMER_TYPE_NI_CERT_REQUEST, 
                  nbr, FALSE);
    an_timer_init(&nbr->cert_revalidate_timer, AN_TIMER_TYPE_REVALIDATE_CERT, 
                  nbr, FALSE);
    an_timer_init(&nbr->cert_expire_timer, AN_TIMER_TYPE_NBR_CERT_EXPIRE,
                  nbr, FALSE);
    nbr->num_of_links = 0;
    nbr->renew_cert_poll_count = 0;
    nbr->my_cert_expired_time = 0;
    nbr->renew_cert_5perc_poll_timer = 0;
    nbr->renew_cert_1perc_poll_timer = 0;
    nbr->validation.result = AN_CERT_VALIDITY_UNKNOWN;
    nbr->select_anr_retry_count = 0;
    for(index = AN_SERVICE_AAA; index<AN_SERVICE_MAX; index++) {
        nbr->an_nbr_srvc_list[index].srvc_ip = AN_ADDR_ZERO;
        nbr->an_nbr_srvc_list[index].sync_done = FALSE;
        an_timer_init(&nbr->an_nbr_srvc_list[index].cleanup_timer, 
                      AN_TIMER_TYPE_AAA_INFO_SYNC + index, nbr, FALSE);
    }
}

an_nbr_t* 
an_nbr_alloc (void)
{
    an_nbr_t *nbr = NULL;

    if (!an_nbr_pool) {
        /* Allocate AN NBR chunk pool */
        an_nbr_pool = an_mem_chunkpool_create(sizeof(an_nbr_t),
                              AN_NBR_POOL_SIZE, "AN NBR ChunkPool");
    }

    /* Try to allocate a AN NBR */
    nbr = an_mem_chunk_malloc(an_nbr_pool);
    if (!nbr) {
        if (an_mem_chunkpool_destroyable(an_nbr_pool)) {
            an_mem_chunkpool_destroy(an_nbr_pool);
            an_nbr_pool = NULL;
        }
        return (NULL);
    }

    an_nbr_alloc_init(nbr);
    return (nbr);
} 


static void
an_nbr_free_cleanup (an_nbr_t *nbr)
{
    int32_t index = 0;
    an_cerrno retcode;

    if (nbr->udi.data) an_free_guard(nbr->udi.data);
    if (nbr->sudi.data) an_free_guard(nbr->sudi.data);
    if (nbr->domain_cert.data) an_free_guard(nbr->domain_cert.data);
    if (nbr->device_id) an_free_guard(nbr->device_id);
    if (nbr->domain_id) an_free_guard(nbr->domain_id);

    an_nbr_link_db_destroy(nbr->an_nbr_link_list);

    if (an_list_is_valid(nbr->an_nbr_link_list)) {
         retcode = an_list_destroy(&nbr->an_nbr_link_list);
         if (AN_CERR_SUCCESS != retcode) {
             DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                          "\n%sNbr Link DB destroy failed",
                          an_nd_db);
         } else {
             DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                          "\n%sNbr Link DB destroy successful",
                          an_nd_db);
             nbr->an_nbr_link_list = NULL;
         }
    }
    
    an_timer_stop(&nbr->cert_request_timer);
    an_timer_stop(&nbr->cert_revalidate_timer);
    an_timer_stop(&nbr->cert_expire_timer);
    for(index = AN_SERVICE_AAA; index<AN_SERVICE_MAX; index++) {
        an_timer_stop(&nbr->an_nbr_srvc_list[index].cleanup_timer);
    }
}

void
an_nbr_free (an_nbr_t *nbr)
{
    if (!nbr) {
        return;
    }

    an_nbr_free_cleanup(nbr);
    an_mem_chunk_free(&an_nbr_pool, nbr);
}

an_avl_compare_e 
an_nbr_compare (an_avl_node_t *node1, an_avl_node_t *node2)
{
    an_nbr_t *nbr1 = (an_nbr_t *)node1;
    an_nbr_t *nbr2 = (an_nbr_t *)node2;
    int comp = 0;

    if (!nbr1 && !nbr2) {
        return (AN_AVL_COMPARE_EQ);
    } else if (!nbr1) {
        return (AN_AVL_COMPARE_LT);
    } else if (!nbr2) {
        return (AN_AVL_COMPARE_GT);
    }

    if (nbr1->udi.len < nbr2->udi.len) {
        return (AN_AVL_COMPARE_LT);
    } else if (nbr1->udi.len > nbr2->udi.len) {
        return (AN_AVL_COMPARE_GT);
    } else { 
        an_strcmp_s(nbr1->udi.data, AN_UDI_MAX_LEN, nbr2->udi.data, &comp);
        if (comp < 0) {
            return (AN_AVL_COMPARE_LT);
        } else if (comp > 0) {
            return (AN_AVL_COMPARE_GT);
        } else {
            return (AN_AVL_COMPARE_EQ);
        }
    }
}

boolean
an_nbr_db_insert (an_nbr_t *nbr)
{
    if (!nbr) {
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sInserting Nbr [%s] into Nbr DB", 
                 an_nd_db, nbr->udi.data); 
    an_avl_insert_node((an_avl_top_p *)&an_nbr_database,
                  (an_avl_node_t *)nbr, an_nbr_compare, &an_nbr_tree); 

    //topo_nbr_connect(nbr);
    return (TRUE);
}

boolean
an_nbr_db_remove (an_nbr_t *nbr)
{
    if (!nbr) {
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                 "\n%sRemoving Nbr [%s] from Nbr DB", an_nd_db, nbr->udi.data);

    an_avl_remove_node((an_avl_top_p *)&an_nbr_database,
                  (an_avl_node_t *)nbr, an_nbr_compare, &an_nbr_tree); 

    return (TRUE);
}

static an_cerrno
an_nbr_expire_link (an_list_t *list,
        const an_list_element_t *current,
        an_list_element_t *next, void *context)
{
    an_nbr_link_spec_t *current_link = NULL;

    if (!current) {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sInvalid input params to expire the link in the Nbr " 
                     "Link DB", an_nd_db);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    current_link = (an_nbr_link_spec_t *)current->data;

    if (!an_timer_is_expired(&current_link->cleanup_timer)) {
        an_timer_start(&current_link->cleanup_timer, AN_NBR_LINK_EXPIRE_IMMEDIATE);
    }
    return (AN_CERR_SUCCESS);
}

void
an_nbr_expire_nbr (an_nbr_t *nbr)
{
    
    if (!nbr)
    {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNull Nbr input params, " 
                     "can't expire the Nbr entry from the Nbr DB", an_nd_db);
        return;
    }

    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, "\n%sExpiring Nbr[%s] "
                 "Entry from the Nbr DB", an_nd_db, nbr->udi.data); 
   
    an_nbr_link_db_walk(nbr->an_nbr_link_list, an_nbr_expire_link, NULL); 
}

void 
an_nbr_remove_and_free_nbr (an_nbr_t *nbr)
{
    if (!nbr)
    {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull Nbr Input Params", an_nd_db);
        return;
    }
    
    an_nbr_db_remove(nbr);
    an_nbr_free(nbr); 
}

an_nbr_t *
an_nbr_db_search (an_udi_t udi)
{
    an_nbr_t goal_nbr = {};
    an_nbr_t *nbr = NULL;

    an_avl_node_t *avl_type  = (an_avl_node_t *)&goal_nbr;
    
    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_INFO, NULL, 
                 "\n%sSearching Nbr [%s] in Nbr DB", an_nd_db, udi.data);
   
    an_memcpy_s(&goal_nbr.udi, sizeof(an_udi_t), &udi, sizeof(an_udi_t));
    nbr = (an_nbr_t *)
          an_avl_search_node((an_avl_top_p)an_nbr_database,
                             avl_type, an_nbr_compare, &an_nbr_tree); 
    return (nbr);
}

void
an_nbr_db_walk (an_avl_walk_f walk_func, void *args)
{
    an_avl_walk_all_nodes((an_avl_top_p *)&an_nbr_database, walk_func, 
                          an_nbr_compare, args, &an_nbr_tree);    
}

an_avl_walk_e
an_nbr_db_init_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;

    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }

    an_nbr_expire_nbr(nbr);

    return (AN_AVL_WALK_SUCCESS);
}

void
an_nbr_db_init (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sInitializing the Nbr DB", an_nd_db);
    an_nbr_db_walk(an_nbr_db_init_cb, NULL);
}

void 
an_nbr_set_service_info (an_nbr_t *nbr, an_service_info_t *srvc_info)
{
     an_service_type_e srvc_type = srvc_info->srvc_type;
     an_nbr_service_info_t *nbr_srvc_info;

     if (srvc_type < AN_SERVICE_AAA || srvc_type >= AN_SERVICE_MAX) {
        an_log(AN_LOG_SRVC, "\nInvalid service type");
        return;
     }

     nbr_srvc_info = &nbr->an_nbr_srvc_list[srvc_type]; 
     an_memcpy_s((uint8_t *)&nbr_srvc_info->srvc_ip, sizeof(an_addr_t),
                    (uint8_t *)&srvc_info->srvc_ip, sizeof(an_addr_t));
     nbr_srvc_info->sync_done = TRUE;
     nbr_srvc_info->retries_done = 0;

}

boolean
an_nbr_get_addr_and_ifs (an_nbr_t *nbr, an_addr_t *addr_p, 
                    an_if_t *local_if_p, uint8_t **remote_if)
{
    an_nbr_link_spec_t *first_link = NULL;

    if (!nbr) {
        return (FALSE);
    }

    if (!an_list_is_valid(nbr->an_nbr_link_list)) {
        return (FALSE);
    }    

    first_link = (an_nbr_link_spec_t *)an_list_get_data(
                            an_list_get_head_elem(nbr->an_nbr_link_list));
    if (!first_link) {
        return (FALSE);
    }

    if (addr_p) {
        *addr_p = first_link->ipaddr;
    }
    if (local_if_p) {
        *local_if_p = first_link->local_ifhndl;
    }
    if (remote_if) {
        *remote_if = first_link->nbr_if_name;
    }

    return (TRUE);
}

an_nbr_link_spec_t* an_nbr_link_db_alloc_node (void)
{
    an_nbr_link_spec_t *nbr_link_data = NULL;

    nbr_link_data = an_malloc_guard(sizeof(an_nbr_link_spec_t),
                                      "AN NBR Interface");
    if (nbr_link_data == NULL)
    {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sMemory Alloc failed for the Nbr Link DB entry", an_nd_db);
        return (FALSE);
    }
    
    an_memset_guard_s(nbr_link_data, 0 , sizeof(an_nbr_link_spec_t));
    return (nbr_link_data);
}

void
an_nbr_link_db_free_node (an_nbr_link_spec_t *curr_nbr_link_data)
{
    if (curr_nbr_link_data->nbr_if_name) {
        an_free_guard(curr_nbr_link_data->nbr_if_name);
        curr_nbr_link_data->nbr_if_name = NULL;
    }
    an_free_guard(curr_nbr_link_data);
}

an_cerrno
an_nbr_link_db_stop_timer_and_remove_node (an_list_t *list,
                         const an_list_element_t *current,
                         an_nbr_link_spec_t *curr_data)
{

    if (!list || !current || !curr_data)
    {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sInvalid input params to remove the link in the Nbr " 
                     "Link DB", an_nd_db);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    an_timer_stop(&curr_data->cleanup_timer);

    //remove the specific element
    if (!an_list_remove(list, (an_list_element_t *)current, curr_data))
    {
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    } else {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sInterface %s removed successfully", an_nd_db, 
                     an_if_get_name(curr_data->local_ifhndl));
    }
    return (AN_CERR_SUCCESS);
}

boolean
an_nbr_link_db_create (an_nbr_t *nbr)
{
    if (!nbr->an_nbr_link_list) {
        if (AN_CERR_SUCCESS != an_list_create(&nbr->an_nbr_link_list,
                              "AN Nbr Link DB")) {
            DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                         "\n%sNbr [%s] Link DB creation failed", 
                         an_nd_db, nbr->udi.data);
            return (FALSE);
        }
        else {
            DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                         "\n%sNbr [%s] Link DB created succesfully",
                         an_nd_db, nbr->udi.data);
            return (TRUE);
        }
    }
    return (TRUE);
}

static an_cerrno
an_nbr_link_remove_and_free_all_nodes_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_nbr_link_spec_t *curr_data = NULL;
    an_cerrno ret = AN_CERR_SUCCESS;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNull input params to remove link in the "
                     "Nbr Link DB", an_nd_db);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    curr_data = (an_nbr_link_spec_t *) current->data;
    if (list && current) {
 
        ret = an_nbr_link_db_stop_timer_and_remove_node(list, current,
                                                       curr_data);   
        if (ret != AN_CERR_SUCCESS)
        {
            DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                         "\n%sFailed to remove the nbr link %s from the " 
                         "Nbr Link DB", an_nd_db, 
                         an_if_get_name(curr_data->local_ifhndl));
        }
        an_nbr_link_db_free_node(curr_data);
        return (ret);
    }
    return (AN_CERR_V_FATAL(0, 0, EINVAL));
}

an_cerrno
an_nbr_link_db_destroy (an_list_t *list)
{
    an_cerrno ret;
    /*
     * Walk list of nbr ifhndl structs and free all memory
    */

    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                 "\n%sWalking the Nbr DB to destroy the Nbr Link DB",
                 an_nd_db);
    
    ret = an_nbr_link_db_walk(list, an_nbr_link_remove_and_free_all_nodes_cb,
                              NULL);

    if (an_list_is_empty(list))
    {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sNbr Link DB is empty", an_nd_db);
    }

    return (ret);
}

boolean
an_nbr_link_db_insert (an_list_t *list, an_nbr_link_spec_t *nbr_link_data,
        an_if_t local_ifhndl,                           
        an_addr_t if_ipaddr, uint8_t *remote_if_name)
{
    uint16_t remote_if_name_len = 0;

    if (!an_list_is_valid(list)) {
       DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                    "\n%sInvalid Nbr Link DB", an_nd_db); 
       return (FALSE);
    }

    remote_if_name_len = an_strlen(remote_if_name) + 1; 
    nbr_link_data->nbr_if_name = an_malloc_guard(remote_if_name_len, 
                                        "NBR Link Remote If name"); 
    if (!nbr_link_data->nbr_if_name) {
        an_free_guard(nbr_link_data);
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sMem Alloc failed for Nbr link interface name", 
                     an_nd_db);
        return (FALSE);
    }
    an_memcpy_guard_s(nbr_link_data->nbr_if_name, remote_if_name_len, remote_if_name,     
                                                           remote_if_name_len);
   
    nbr_link_data->ipaddr = if_ipaddr;
    nbr_link_data->local_ifhndl = local_ifhndl;
    
    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                  "\n%sNew Link with [Local If_name = %s] [Remote If_name = %s] "
                  "[IPaddr = %s] inserted to the Nbr Link DB", an_nd_db, 
                  an_if_get_name(local_ifhndl), remote_if_name, 
                  an_addr_get_string(&if_ipaddr));
    
    an_list_enqueue_node(list, nbr_link_data);
    an_acp_init_acp_info_per_nbr_link(nbr_link_data);
    
    return (TRUE);
}

static int 
an_nbr_link_search_cb (void *data1, void *data2)
{
    an_nbr_link_spec_t *ctx1 = NULL;
    an_nbr_link_spec_t *ctx2 = NULL;
    int res = -1;

    if ((NULL == data1) || (NULL == data2)) {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sInvalid params, link search in Nbr Link DB "
                     "failed", an_nd_db);
        return (-1);
    }

    ctx1 = (an_nbr_link_spec_t *)data1;
    ctx2 = (an_nbr_link_spec_t *)data2;

    an_memcmp_s(&ctx1->ipaddr,sizeof(an_addr_t),
                              &ctx2->ipaddr, sizeof(an_addr_t), &res);

/*    an_log(AN_LOG_NBR_LINK,"\n%scomparing the interfaces %s and %s",
            an_nbr_link_prefix, an_if_get_name(ctx1->local_ifhndl), 
            an_if_get_name(ctx2->local_ifhndl));
    an_log(AN_LOG_NBR_LINK,"\n%scomparing addr %s and %s", 
            an_nbr_link_prefix, an_addr_get_string(&ctx1->ipaddr), 
            an_addr_get_string(&ctx2->ipaddr));
*/
    if (res==0  && (ctx1->local_ifhndl == ctx2->local_ifhndl))
    {
        return (0);
    }else {
        return (1);
    }
}

an_nbr_link_spec_t*
an_nbr_link_db_search (an_list_t *list, an_if_t ifhndl, an_addr_t addr)
{
    an_nbr_link_spec_t goal;
    an_nbr_link_spec_t *found_data = NULL;

    an_memset_s(&goal, 0, sizeof(an_nbr_link_spec_t));
    
    goal.local_ifhndl= ifhndl;
    goal.ipaddr = addr;
    
    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_INFO, NULL,
                 "\n%sSearching the interface %s in the Nbr Link DB",
                 an_nd_db, an_if_get_name(ifhndl));

    found_data = (an_nbr_link_spec_t *) an_list_lookup_node(list, NULL,
            (void *)&(goal), an_nbr_link_search_cb);
    
    return (found_data);
}

static an_cerrno
an_nbr_link_remove_node_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_nbr_link_spec_t *if_data = NULL;
    an_nbr_link_spec_t *curr_data = NULL;
    an_cerrno ret = AN_CERR_SUCCESS;
     
    if_data = (an_nbr_link_spec_t *) context;

    if (current == NULL || list == NULL || if_data == NULL)    {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull Input params to remove the link ",
                     "from the Nbr Link DB", an_nd_db);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    curr_data = (an_nbr_link_spec_t *) current->data;

    if (list && current) {
       an_log(AN_LOG_NBR_LINK, "\n%sCurr interface %s %s",
                                an_nbr_link_prefix,
                                an_if_get_name(curr_data->local_ifhndl),
                                an_addr_get_string(&curr_data->ipaddr));
       an_log(AN_LOG_NBR_LINK, "\n%sArg interface %s %s",
                                an_nbr_link_prefix,
                                an_if_get_name(if_data->local_ifhndl),
                                an_addr_get_string(&if_data->ipaddr));
     
       if (if_data->local_ifhndl == curr_data->local_ifhndl)
       {
           DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                        "\n%sInterface [%s] found with Ipaddr [%s] for removal",
                        an_nd_db, an_if_get_name(curr_data->local_ifhndl),
                        an_addr_get_string(&curr_data->ipaddr));
          
           ret = an_nbr_link_db_stop_timer_and_remove_node(list, current,
                                                       curr_data);
           
           if (ret != AN_CERR_SUCCESS)
           {
                DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                             "\n%sFailed to remove nbr link [%s] from the "
                             "Nbr Link DB", an_nd_db, 
                             an_if_get_name(curr_data->local_ifhndl));
           }
           return (ret);
       }
       //return success to continue walk
       return (AN_CERR_SUCCESS);
    }
    return (AN_CERR_V_FATAL(0, 0, EINVAL));
}

void
an_nbr_link_db_remove (an_list_t *list, an_nbr_link_spec_t *nbr_link_data)
{
    an_cerrno ret;

    if (list == NULL || nbr_link_data == NULL)    {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNbr Link DB empty, " 
                     "can't remove link", an_nd_db);
        return;
    }

    DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sWalking the Nbr Link DB to remove the interface " 
                 "%s of IPaddr %s", an_nd_db, 
                 an_if_get_name(nbr_link_data->local_ifhndl),
                 an_addr_get_string(&nbr_link_data->ipaddr));

    //walk the list and delete the interface
    ret = an_nbr_link_db_walk(list, an_nbr_link_remove_node_cb,
                             nbr_link_data);
 
    if (an_list_is_empty(list))
    {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNbr Link DB is empty", an_nd_db);
    }

    return;
}

an_cerrno
an_nbr_link_db_walk (an_list_t *list, an_list_walk_handler callback_func,
                     void *nbr_link_data)
{
    an_cerrno ret;
    //walk the list and pass the list elem to the callback func
    ret = AN_CERR_POSIX_ERROR(an_list_walk(list,
                callback_func,
                nbr_link_data));
    return (ret);
}

boolean
an_nbr_link_db_is_empty (an_nbr_t *nbr)
{
    if (!nbr)
    {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNull nbr input params, can't empty Nbr Link DB",
                     an_nd_db);
        return (FALSE);
    }

    if (an_list_is_empty(nbr->an_nbr_link_list))
    {
       return (TRUE);
    }
    return (FALSE);
}
