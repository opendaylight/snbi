/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_if_linux.h>
#include <an_if.h>
#include <an.h>
#include <an_logger.h>
#include <an_timer.h>
#include <an_l2_linux.h>
#include <an_if_mgr.h>
#include <an_mem.h>
#include <an_nd.h>
#include <olibc_addr.h>
#include <olibc_if_event.h>
#include <an_proc_linux.h>

#define AN_LOOP_VIS_BW 8000000
extern an_avl_tree  an_if_info_tree;

olibc_list_hdl an_if_linux_list_hdl = NULL;
olibc_if_event_listener_hdl an_if_event_listener_hdl = NULL;

static
olibc_list_cbk_return_t
an_if_node_compare_cbk (void *data1, void *data2)
{
    an_if_linux_info_t *an_linux_if_info1, *an_linux_if_info2;

    if (!data1 || !data2) {
        return (OLIBC_LIST_CBK_RET_STOP);
    }

    an_linux_if_info1 = data1;
    an_linux_if_info2 = data2;

    if (an_linux_if_info1->if_index == an_linux_if_info2->if_index) {
        return (OLIBC_LIST_CBK_RET_EQUAL);
    }
    return OLIBC_LIST_CBK_RET_CONTINUE;
}

static an_if_linux_info_t*
an_if_linux_get_info (an_if_t ifhndl)
{
    olibc_retval_t retval;
    an_if_linux_info_t *an_linux_if_info = NULL, an_compare_if_info;

    memset(&an_compare_if_info, 0, sizeof(an_if_linux_info_t));

    an_compare_if_info.if_index = ifhndl;

    retval = olibc_list_lookup_node(an_if_linux_list_hdl, &an_compare_if_info,
                                    an_if_node_compare_cbk, (void **)&an_linux_if_info);

    if (retval != OLIBC_RETVAL_SUCCESS || !an_linux_if_info) {
        return NULL;
    }

    return (an_linux_if_info);
}
inline const uint8_t * an_if_get_short_name (an_if_t ifhndl)
{
    return (an_if_get_name(ifhndl));
}

an_v6addr_t
an_if_linux_get_ipv6_ll (an_if_t ifhndl)
{
    an_if_linux_info_t *an_linux_if_info = NULL;
    olibc_list_iterator_hdl if_list_iter = NULL;
    olibc_addr_info_t *addr_info_ptr = NULL;
    olibc_retval_t retval;

    an_linux_if_info = an_if_linux_get_info(ifhndl);

    if (!an_linux_if_info) {
        return AN_V6ADDR_ZERO;
    }

    retval = olibc_list_iterator_create(an_linux_if_info->if_addr_list_hdl,
                                        &if_list_iter);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return AN_V6ADDR_ZERO;
    }
    while (olibc_list_iterator_get_next(if_list_iter,
                                        (void **)&addr_info_ptr) ==
            OLIBC_RETVAL_SUCCESS) {
        if (addr_info_ptr &&
            addr_info_ptr->addr_family == AF_INET6 &&
            addr_info_ptr->scope == OLIBC_ADDR_SCOPE_LINK) {
            return addr_info_ptr->addrv6;
        }
    }
    return AN_V6ADDR_ZERO;
}

inline const uint8_t * an_if_get_name (an_if_t ifhndl)
{
    an_if_linux_info_t *an_linux_if_info = NULL;

    an_linux_if_info = an_if_linux_get_info(ifhndl);

    if (!an_linux_if_info) {
        return NULL;
    }
    return (an_linux_if_info->if_name);
}

inline boolean an_if_is_up (an_if_t ifhndl)
{
    an_if_linux_info_t *an_linux_if_info = NULL;

    an_linux_if_info = an_if_linux_get_info(ifhndl);

    if (!an_linux_if_info) {
        return FALSE;
    }
    return (an_linux_if_info->if_state == IF_UP);
}

an_if_t
an_if_check_vlan_exists (uint32_t unit)
{
    return (0);
}

boolean
an_if_check_loopback_exists (uint32_t unit)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return (FALSE);
}

void
an_if_platform_specific_cfg (an_if_t ifhndl)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

boolean an_if_bring_up (an_if_t ifhndl)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return (TRUE);
}

inline boolean an_if_is_tunnel (an_if_t ifhndl)
{
    an_if_linux_info_t *an_linux_if_info = NULL;

    an_linux_if_info = an_if_linux_get_info(ifhndl);

    if (!an_linux_if_info) {
        return FALSE;
    }
    return (an_linux_if_info->is_tunnel);
}


boolean
an_if_is_loopback (an_if_t ifhndl)
{
    an_if_linux_info_t *an_linux_if_info = NULL;

    an_linux_if_info = an_if_linux_get_info(ifhndl);

    if (!an_linux_if_info) {
        return FALSE;
    }
    return (an_linux_if_info->is_loopback);
}

void
an_if_enable_nd_on_intf (an_if_linux_info_t *if_linux_info)
{
    if (!if_linux_info) {
        return;
    }
    if (if_linux_info->hw_type != OLIBC_HW_IF_TYPE_ETHERNET) {
        return;
    }

    an_nd_set_preference(if_linux_info->if_index, AN_ND_CLIENT_CLI,
            AN_ND_CFG_ENABLED);
    an_nd_startorstop(if_linux_info->if_index);
}

void
an_if_enable_nd_on_all_intfs (void)
{
    olibc_retval_t retval;
    an_if_linux_info_t *if_linux_info = NULL;
    olibc_list_iterator_hdl if_list_iter = NULL;

    retval = olibc_list_iterator_create(an_if_linux_list_hdl, &if_list_iter);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return;
    }
    while (olibc_list_iterator_get_next(if_list_iter,
                                        (void **)&if_linux_info) ==
            OLIBC_RETVAL_SUCCESS) {
        an_if_enable_nd_on_intf(if_linux_info);
    }
    olibc_list_iterator_destroy(&if_list_iter);
    return;
}

void
an_if_walk (an_if_walk_func func, void *data)
{
    olibc_retval_t retval;
    an_if_linux_info_t *if_linux_info = NULL;
    olibc_list_iterator_hdl if_list_iter = NULL;

    retval = olibc_list_iterator_create(an_if_linux_list_hdl, &if_list_iter);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return;
    }
    while (olibc_list_iterator_get_next(if_list_iter,
                                        (void **)&if_linux_info) ==
            OLIBC_RETVAL_SUCCESS) {
        func(if_linux_info->if_index, data);
    }
    olibc_list_iterator_destroy(&if_list_iter);
    return;
}

boolean
an_if_is_ethernet (an_if_t ifhndl)
{
    an_if_linux_info_t *an_linux_if_info = NULL;

    an_linux_if_info = an_if_linux_get_info(ifhndl);

    if (!an_linux_if_info) {
        return FALSE;
    }
    return (an_linux_if_info->hw_type == OLIBC_HW_IF_TYPE_ETHERNET);
}

boolean
an_if_make_volatile (an_if_t ifhndl)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return (TRUE);
}

an_if_t
an_if_create_loopback (uint32_t unit)
{
    an_if_info_t *if_info;
    an_if_t if_index = 0;
    an_if_linux_info_t *if_linux_info;
    olibc_retval_t retval;

    system("ip link add snbi-fe type dummy");
    system("ip link set dev snbi-fe up");

    retval = olibc_malloc((void **)&if_linux_info,
                    sizeof(an_if_linux_info_t), "AN linux info");

    if (!if_linux_info) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%s AN If creation failed", an_nd_event);
            return 0;
    }

    memcpy(if_linux_info->if_name, "snbi-fe", strlen("snbi-fe")+1);
    if_index = if_nametoindex("snbi-fe");
    if_linux_info->if_index = if_index;
    if_linux_info->if_state = IF_UP;
    if_linux_info->is_loopback = TRUE;
    if_linux_info->is_tunnel = FALSE;

    retval = olibc_list_insert_node(an_if_linux_list_hdl, NULL,
                                    if_linux_info);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%s AN interface insert failed", an_nd_event);
        return 0;
    }

    if_info = an_if_info_db_search(if_index, TRUE);
    if (if_info) {
        if_info->autonomically_created = TRUE;
        an_log(AN_LOG_ACP, "\nAN: Loopback - New name snbi-fe");
               
    } else {
        an_log(AN_LOG_ERR, "\nAN: Loopback - New name snbi-fe , No IFINFO");
    }

    return (if_index);
}

an_if_t
an_get_autonomic_loopback_ifhndl(void)
{
    return(if_nametoindex("snbi-fe"));
}

void
an_if_remove_loopback (an_if_t lb_ifhndl)
{
    system("ip link delete snbi-fe type dummy");
}

 /*
  * This function is used to check whether the idb is loopback idb
  * or not. This is used while recycling the idb.
  */
boolean
an_if_recycle_matcher (an_idbtype *idb)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
   return FALSE;
}

/* This function clears already created idb sub-blocks.
 */

void
clear_idb_subblocks (an_idbtype *idb)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

uint8_t*
an_if_get_l2_mac_addr (an_hwidbtype *hwidb)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return (NULL);
}

void
an_if_set_svi_mac_addr (an_hwidbtype *hwidb, uint8_t* l2_mac)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

an_idbtype * an_if_number_to_swidb(an_if_t ifhndl)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
   return(NULL);
}

void an_set_if_vlanid (an_if_info_t *an_if_info, ushort vlanid)
{
    return;
}

void an_set_if_inner_vlanid (an_if_info_t *an_if_info, ushort inner_vlanid)
{
    return;
}
/*
boolean
an_should_bring_up_interfaces (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}
*/

void
an_if_list_linux_init (void)
{
    olibc_if_event_type_t event_type;
    olibc_retval_t retval;
    olibc_if_info_t if_info;
    olibc_if_iterator_filter_t if_iter_filter;
    olibc_if_iterator_hdl if_iter_hdl = NULL;
    an_if_linux_info_t *if_linux_info;

    retval = olibc_list_create(&an_if_linux_list_hdl, "AN if list");
    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%s AN If list creation failed", an_nd_event);
        return;
    }
    memset(&if_iter_filter, 0, sizeof(olibc_if_iterator_filter_t));
    if_iter_filter.flags = OLIBC_FLAG_IPV4 | OLIBC_FLAG_IPV6;

    retval = olibc_if_iterator_create(&if_iter_filter, &if_iter_hdl);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%s AN If iterator creation failed", an_nd_event);
        olibc_list_destroy(&an_if_linux_list_hdl, NULL);
        return;
    }

    memset(&if_info, 0, sizeof(olibc_if_info_t));
    while (olibc_if_iterator_get_next(if_iter_hdl, (void *)&if_info, 
           &event_type) ==
            OLIBC_RETVAL_SUCCESS) {

        retval = olibc_malloc((void **)&if_linux_info,
                              sizeof(an_if_linux_info_t),
                             "AN linux info");

        if (!if_linux_info) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%s AN If creation failed", an_nd_event);
            olibc_if_iterator_destroy(&if_iter_hdl);
            return;
        }
        if (event_type == IF_EVENT_DEL_LINK) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%s AN If init DEL event received", an_nd_event);
            continue;
        }

        memcpy(if_linux_info->if_name, if_info.if_name, AN_IF_NAME_LEN);
        printf("\n New interface added %d",if_info.if_index);
        if_linux_info->if_index = if_info.if_index;
        if_linux_info->if_state = if_info.if_state;
        if_linux_info->is_loopback = if_info.is_loopback;
        if_linux_info->hw_type = if_info.hw_type;
        if_linux_info->if_addr_list_hdl = NULL;
        memcpy(if_linux_info->hw_addr, if_info.hw_addr, AN_IF_HW_ADDR_LEN);
        if_linux_info->hw_addr_len = if_info.hw_addr_len;

        retval = olibc_list_insert_node(an_if_linux_list_hdl, NULL,
                                        if_linux_info);

        if (retval != OLIBC_RETVAL_SUCCESS) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%s AN interface insert failed", an_nd_event);
            olibc_if_iterator_destroy(&if_iter_hdl);
            return;
        }

        memset(&if_info, 0, sizeof(olibc_if_info_t));
    }
    olibc_if_iterator_destroy(&if_iter_hdl);
}

void
an_if_list_addr_linux_init (void)
{
    uint32_t if_index;
    olibc_retval_t retval;
    olibc_addr_info_t addr_info, *addr_info_ptr;
    olibc_addr_iterator_hdl iter_hdl;
    olibc_addr_iterator_filter_t filter;
    an_if_linux_info_t *an_linux_if_info = NULL;

    memset(&filter, 0 , sizeof(olibc_addr_iterator_filter_t));

    filter.flags = OLIBC_FLAG_IPV6;
    retval = olibc_addr_iterator_create(&filter, &iter_hdl);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return;
    }

    memset(&addr_info, 0, sizeof(olibc_addr_info_t));
    while (olibc_addr_iterator_get_next(iter_hdl, &addr_info, &if_index)
            == OLIBC_RETVAL_SUCCESS) {
        if (addr_info.addr_family != AF_INET6) {
            continue;
        }

        if (!an_linux_if_info ||
            (an_linux_if_info && an_linux_if_info->if_index != if_index)) {
            an_linux_if_info = an_if_linux_get_info(if_index);
        }

        if (!an_linux_if_info) {
            continue;
        }

        if (!an_linux_if_info->if_addr_list_hdl) {
            retval = olibc_list_create(&an_linux_if_info->if_addr_list_hdl,
                                       "AN IF addr list");
            if (retval != OLIBC_RETVAL_SUCCESS) {
                continue;
            }
        }
        if ((addr_info.addr_family == AF_INET6) &&
            (addr_info.scope == OLIBC_ADDR_SCOPE_LINK)) {
            retval = olibc_malloc((void **)&addr_info_ptr,
                                  sizeof(olibc_addr_info_t),
                                  "AN IF addr info");
            if (retval != OLIBC_RETVAL_SUCCESS) {
                continue;
            }

            memcpy(addr_info_ptr, &addr_info, sizeof(olibc_addr_info_t));
            retval = olibc_list_insert_node(an_linux_if_info->if_addr_list_hdl,
                                            NULL, addr_info_ptr);

        }
        memset(&addr_info, 0, sizeof(olibc_addr_info_t));
    }
    olibc_addr_iterator_destroy(&iter_hdl);
}

boolean
an_if_event_enqueue (uint32_t state, uint64_t if_index)
{
    olibc_retval_t retval;
    if (!an_pmsg_q_hdl) {
        return FALSE;
    }

    retval = olibc_msg_q_enqueue(an_pmsg_q_hdl, state,
                                 if_index, NULL);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }
    return TRUE;
}

static
olibc_list_cbk_return_t
an_if_addr_linux_free_func (void *data)
{
    olibc_addr_info_t *addr_info_ptr = NULL;

    if (!data) {
        return OLIBC_LIST_CBK_RET_STOP;
    }
    addr_info_ptr = (olibc_addr_info_t *) data;

    olibc_free((void **)&addr_info_ptr);
    return OLIBC_LIST_CBK_RET_CONTINUE;
}

static
olibc_list_cbk_return_t
an_if_linux_free_func (void *data)
{
    an_if_linux_info_t *if_info = NULL;

    if_info = (an_if_linux_info_t *)data;

    if (if_info->if_addr_list_hdl) {
        olibc_list_destroy(&if_info->if_addr_list_hdl,
                an_if_addr_linux_free_func);
    }

    if (if_info) {
        olibc_free((void **)&if_info);
    }

    return OLIBC_LIST_CBK_RET_CONTINUE;
}

static boolean
an_interface_event_cbk (olibc_if_event_hdl if_event)
{
    olibc_if_info_t if_info;
    olibc_if_iterator_hdl if_iterator_hdl = NULL;
    an_if_linux_info_t *if_linux_info, tmp_if_linux_info;
    olibc_if_event_type_t event_type;
    olibc_retval_t retval;
    uint32_t if_state;
    uint64_t if_index;
    boolean new_interface = FALSE;

    if (!if_event) {
        return FALSE;
    }

    retval = olibc_if_event_get_if_iterator (if_event,
        &if_iterator_hdl);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%s Failed to get interface iterator handle", an_nd_event);
        return FALSE;
    }


    memset(&if_info, 0, sizeof(olibc_if_info_t));
    while (olibc_if_iterator_get_next(if_iterator_hdl, (void *)&if_info,
                &event_type) == OLIBC_RETVAL_SUCCESS) {
        printf("\n Received event for %d event type %d \n", 
                if_info.if_index, event_type);
        if (event_type == IF_EVENT_NEW_LINK) {
            if_linux_info = an_if_linux_get_info(if_info.if_index); 
            if (!if_linux_info) {
                retval = olibc_malloc((void **)&if_linux_info,
                                  sizeof(an_if_linux_info_t),
                                  "AN linux info");
                new_interface = TRUE;
            }

            if (!if_linux_info) {
                DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%s AN If creation failed", an_nd_event);
                return FALSE;
            } 
            memcpy(if_linux_info->if_name, if_info.if_name, AN_IF_NAME_LEN);
            if_linux_info->if_index = if_info.if_index;
            if_linux_info->if_state = if_info.if_state;
            if_linux_info->is_loopback = if_info.is_loopback;
            if_linux_info->hw_type = if_info.hw_type;
            if_linux_info->if_addr_list_hdl = NULL;
            memcpy(if_linux_info->hw_addr, if_info.hw_addr, AN_IF_HW_ADDR_LEN);
            if_linux_info->hw_addr_len = if_info.hw_addr_len;

            retval = olibc_list_insert_node(an_if_linux_list_hdl, NULL,
                                        if_linux_info); 
            if (retval != OLIBC_RETVAL_SUCCESS) {
                DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%s AN interface insert failed", an_nd_event);
                return FALSE;
            } 
            
            if (if_linux_info->if_state == IF_UP) {
                if_state = AN_PMSG_IF_UP;
            } else { 
                if_state = AN_PMSG_IF_DOWN;
            } 
            if_index = if_linux_info->if_index; 
            if (new_interface) {
                an_if_info_db_search(if_linux_info->if_index, TRUE);
                an_if_enable_nd_on_intf(if_linux_info);
            }
        }

        if (event_type == IF_EVENT_DEL_LINK) {
            if_linux_info = NULL;
            tmp_if_linux_info.if_index = if_info.if_index;
            olibc_list_remove_node(an_if_linux_list_hdl,  NULL,
                    &tmp_if_linux_info, an_if_node_compare_cbk,
                    (void **)&if_linux_info);
            if (if_linux_info) {
                if_index = if_linux_info->if_index; 
                an_if_linux_free_func(if_linux_info);
            } else {
                continue;
            }
            if_state = AN_PMSG_IF_ERASED;
        }

        retval = an_if_event_enqueue(if_state, if_index); 
        if (retval != OLIBC_RETVAL_SUCCESS) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%s AN interface handler message enqueue failed",
                    an_nd_event);
            return FALSE;
        }
    }
    return TRUE;

}

void
an_if_event_linux_init (void)
{
    olibc_retval_t retval;
    olibc_if_event_listener_info_t if_event_listener_info;

    memset(&if_event_listener_info, 0, sizeof(olibc_if_event_listener_info_t));

    if_event_listener_info.if_event_listener_cbk =
        an_interface_event_cbk;
    if_event_listener_info.pthread_hdl = an_pthread_hdl;

    retval = olibc_if_event_listener_create(&if_event_listener_info,
            &an_if_event_listener_hdl);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%s AN If event creation failed", an_nd_event);
        return;
    }
}



void an_if_db_linux_init (void)
{
    if (an_if_linux_list_hdl) {
        return;
    }
    an_if_list_linux_init();
    an_if_list_addr_linux_init();
    an_if_event_linux_init();
}
void
an_if_services_init (void)
{
    an_cerrno rc = EOK;

    rc = an_avl_init(&an_if_info_tree, an_if_info_compare);
    if (CERR_IS_NOTOK(rc)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%s AN IF DB Init Failed", an_nd_event);
        return;
    }

    an_if_db_linux_init();
}


void
an_if_services_uninit (void)
{
    olibc_retval_t retval;
    if (an_if_linux_list_hdl) {
        retval = olibc_list_destroy(&an_if_linux_list_hdl,
                                    an_if_linux_free_func);
    }
    return;
}

boolean
an_if_is_acp_interface (an_if_t an_ifhndl)
{
printf("\n[SINO_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}


