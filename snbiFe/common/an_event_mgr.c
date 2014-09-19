/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "../al/an_types.h"
#include "../al/an_if.h"
#include "../al/an_ipv6.h"
#include "../al/an_logger.h"
#include "../al/an_types.h"
#include "../al/an_addr.h"
#include "../al/an_misc.h"
#include "../al/an_pak.h"
#include "an_nd.h"
#include "an_timer.h"
#include "an_acp.h"
#include "an_ni.h"
#include "an_bs.h"
#include "an_nbr_db.h"
#include "an_anra.h"
#include "an_anra_db.h"
#include "an_if_mgr.h"
#include "an.h"
#include "an_event_mgr.h"
//#include "an_topo_disc.h"
#include "../al/an_sudi.h"
#include "../al/an_aaa.h"
#include "../al/an_mem.h"
#include "../al/an_ntp.h"
#include "../al/an_str.h"
#include "../al/an_syslog.h"
//#include "../ios/an_service_discovery.h"
//#include "../ios/an_parse_ios.h"

extern void an_detach_from_environment(boolean called_from_proc);
extern void an_attach_to_environment(void);
extern void an_parser_init(void);
extern void an_event_interface_activated(an_if_t ifhndl);
extern an_avl_tree an_mem_elem_tree;

an_avl_compare_e an_mem_elem_compare(an_avl_node_t *node1, an_avl_node_t *node2);
an_timer an_generictimer = {};

void
an_event_interface_up (an_if_t ifhndl)
{
    an_cert_t domain_cert = {};
    an_if_info_t *an_if_info = NULL;

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sInterface %s is UP", an_nd_event, an_if_get_name(ifhndl));
    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
        return;
    }
    /*
     * On autonomically created or configured interfaces start Adjacency discovery
     */
    if ((an_if_info->autonomically_created) ||
        (AN_ND_CFG_ENABLED == an_nd_state_get(ifhndl))) { 
        an_event_interface_activated(ifhndl);
        return ;
    }
    /*
     * Channel probing happens only on physical interfaces.
     */
    an_get_domain_cert(&domain_cert);

}

void
an_event_interface_down (an_if_t ifhndl)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sInterface %s is DOWN", an_nd_event, 
                 an_if_get_name(ifhndl));

}

void
an_event_interface_erased (an_if_t ifhndl)
{
    an_if_info_t *an_if_info = NULL;

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sInterface %s is Erased", an_nd_event, 
                 an_if_get_name(ifhndl));

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
        return;
    }
    
    an_if_info_db_remove(an_if_info);
    an_if_info_free(an_if_info);
}

void
an_event_registrar_up (void)
{
    an_anra_live_pending();
}

void
an_event_registrar_shut (void)
{
    an_anra_shut_pending();
}

void
an_event_no_registrar (void)
{
    an_anra_delete_pending();
}


void
an_event_autonomics_uninit (boolean flag)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAutonomic uninit", an_nd_event);
    //Disable AN modules
    an_sudi_uninit();
    //topo_disc_uninit(); 
    an_bs_uninit();

    //Stop services before bring down ACP    
    an_discover_services_deallocate();
    an_sd_cfg_global_commands(FALSE);

    /* Reset ACP */
    an_acp_uninit();
    
    /* Reset ND */
    an_nd_uninit();

    /* Final Global Reset */
    an_reset_global_info();

    /* AN DBs Clear */
    an_nbr_db_init();
    an_acp_client_db_init();          
    
    an_if_disable();
    an_platform_specific_uninit();
    an_avl_uninit(&an_mem_elem_tree);

    an_timer_stop(&an_generictimer);
//    an_detach_from_environment(called_from_proc);
//    an_timer_services_uninit(called_from_proc);
}

void
an_event_autonomics_init (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAutonomic init", an_nd_event);
    /* Infra enable for AN */
    //an_logger_init();
    an_log_init();      
    an_timer_services_init();
    an_parser_init();
    an_attach_to_environment();

    an_acp_client_db_init();
    an_nbr_db_init();
    
    /* Final Global Reset */
    an_reset_global_info();

    /* AN Modules enable */
    an_str_buffer_init();
    an_addr_generator_init();
    an_bs_init();
    //topo_disc_init();

    an_timer_init(&an_generictimer, AN_TIMER_TYPE_GENERIC, NULL, FALSE);
    
    if (an_system_is_configured()) {
        an_platform_specific_init();
        an_sudi_init(); 
    }

}

void
an_event_registrar_init (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sRegistrar init", an_nd_event);

    an_logger_init();
    an_timer_services_init();
    an_parser_init();
    an_addr_generator_init();
}

void
an_event_registrar_uninit (void)
{
    return;
}

void
an_event_system_configured (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sSystem configuring", an_nd_event);
    an_platform_specific_init();
    an_if_walk(an_if_platform_specific_cfg_cb, NULL);

    if (an_is_global_cfg_autonomic_enabled()) {
        an_sudi_init();
    }
    if (an_pak_subblock_getsize(AN_PAK_SUBBLOCK_L2_INFO) == 0) { 
        an_pak_subblock_setsize(AN_PAK_SUBBLOCK_L2_INFO, sizeof(an_dot1q_qinq_vlan_id_t));
    }
}

void
an_event_udi_available (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sUDI is available now", an_nd_event);

    an_udi_t my_udi = {};

    if (!an_get_udi(&my_udi)) {
        return;
    }
    an_sd_cfg_global_commands(TRUE);
    an_discover_services(); 

    an_syslog(AN_SYSLOG_UDI_AVAILABLE,my_udi.data);
    if (an_create_trustpoint("MASACRT", "nvram:masa_crt.pem")) {
        an_log(AN_LOG_MASA | AN_LOG_EVENT, 
               "\nAN: Event - Created MASA trustpoint");
    } else {
        an_log(AN_LOG_MASA | AN_LOG_EVENT, 
               "\nAN: Event - Failed to create MASA trustpoint");
    }

    an_if_enable();

    /* uninit ND first, so that any ND using UDI is removed */
    if (an_is_global_cfg_autonomic_enabled()) {


        an_nd_uninit();
        an_nd_init();
    }

    an_timer_start(&an_generictimer, AN_GENERIC_TIMER_INTERVAL);
    an_bs_retrieve_saved_enrollment();
    an_anra_udi_available();
}

void
an_event_sudi_available (void)
{
    an_udi_t my_udi = {};
    
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sSUDI is available now", an_nd_event);
    an_sudi_get_udi(&my_udi);

    an_syslog(AN_SYSLOG_SUDI_AVAILABLE, my_udi.data);

    an_if_enable();

    /* uninit ND first, so that any ND using sUDI is removed */
    if (an_is_global_cfg_autonomic_enabled()) {


        an_nd_uninit();
        an_nd_init();
    }

    an_bs_retrieve_saved_enrollment();
    an_anra_udi_available();
}

void
an_event_ni_cert_request_timer_expired (an_nbr_t *nbr)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sCert Req timer reset for nbr [%s]", 
                 an_nd_event, nbr->udi.data);

    an_ni_cert_request_retry(nbr);
}

void
an_event_hello_refresh_timer_expired (void)
{
    an_nbr_refresh_hello();
}

void
an_event_interface_activated (an_if_t ifhndl)
{
    an_sd_cfg_if_commands(ifhndl, TRUE);
    an_nd_start_on_interface(ifhndl);
}

void
an_event_interface_deactivated (an_if_t ifhndl)
{
    an_nd_stop_on_interface(ifhndl);
}

void
an_event_nbr_link_add (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    if (!nbr || !nbr_link_data) {
       return;
    }
 
    if (!an_acp_is_up_on_nbr_link(nbr_link_data)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%Adding AN Control Plane on the Nbr[%s] link [%s]", 
                     an_nd_event, nbr->udi.data, 
                     an_if_get_name(nbr_link_data->local_ifhndl));
       an_acp_create_per_nbr_link(nbr, nbr_link_data);
       an_acp_create_ipsec_per_nbr_link(nbr, nbr_link_data);
    }
    
    return;
}

void
an_event_nbr_link_lost (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    an_ntp_peer_param_t ntp_peer;

    if (!nbr_link_data || !nbr)
    {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull Input Nbr Link data", an_nd_event);
        return;
    }
    an_syslog(AN_SYSLOG_NBR_LOST,
                  nbr->udi.data, an_if_get_name(nbr_link_data->local_ifhndl));

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sNbr[%s] Link [%s] Lost", an_nd_event, nbr->udi.data,
                 an_if_get_name(nbr_link_data->local_ifhndl));
    ntp_peer.peer_addr = nbr_link_data->ipaddr;
    ntp_peer.ifhdl = nbr_link_data->local_ifhndl;
    (void)an_ntp_remove_peer(&ntp_peer);

    if (an_acp_is_up_on_nbr_link(nbr_link_data)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sRemoving AN Control Plane on the Nbr[%s] link [%s]", 
                     an_nd_event, nbr->udi.data, 
                     an_if_get_name(nbr_link_data->local_ifhndl));
        an_acp_remove_ipsec_per_nbr_link(nbr, nbr_link_data);
        an_acp_remove_per_nbr_link(nbr, nbr_link_data);
    }
    
    //Remove the link and stop the timers
    an_nbr_remove_nbr_link(nbr, nbr_link_data);
}

static an_cerrno
an_event_nbr_link_lost_cb (an_list_t *list,
        const an_list_element_t *current,
        an_list_element_t *next, void *context)
{
    an_nbr_link_context_t *if_data = NULL;
    an_nbr_link_spec_t *curr_data = NULL;
    an_ntp_peer_param_t ntp_peer;
    if_data = (an_nbr_link_context_t *) context;

    if (current == NULL || if_data == NULL)    {
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    curr_data = (an_nbr_link_spec_t *) current->data;
    
    an_syslog(AN_SYSLOG_NBR_LOST,
              if_data->nbr->udi.data, 
              an_if_get_name(curr_data->local_ifhndl));

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sNbr Link lost interface %s", an_nd_event, 
                 an_if_get_name(curr_data->local_ifhndl));
    ntp_peer.peer_addr = curr_data->ipaddr;
    ntp_peer.ifhdl = curr_data->local_ifhndl;
    (void)an_ntp_remove_peer(&ntp_peer);

    if (an_acp_is_up_on_nbr_link(curr_data)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sRemoving AN control plane on link %s",
                     an_nd_event,
                     an_if_get_name(curr_data->local_ifhndl));
        an_acp_remove_ipsec_per_nbr_link(if_data->nbr, curr_data);
        an_acp_remove_per_nbr_link(if_data->nbr, curr_data);
    }
    //Remove the link and stop the timers
    an_nbr_remove_nbr_link(if_data->nbr, curr_data);

    return (AN_CERR_SUCCESS);
}

void 
an_event_nbr_lost (an_nbr_t *nbr)
{
    an_nbr_link_spec_t nbr_link_data;
    an_ntp_peer_param_t ntp_peer;
    an_nbr_link_context_t nbr_link;
    an_cerrno ret;
   
    if (!nbr) {
      return;
    }
   
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sNbr [%s] lost", an_nd_event, nbr->udi.data);

    nbr_link.nbr_link_data = &nbr_link_data;
    nbr_link.nbr = nbr;
    ret = an_nbr_link_db_walk(nbr->an_nbr_link_list, an_event_nbr_link_lost_cb,
                             &nbr_link);

    /* Delete ntp peer over acp */
    ntp_peer.peer_addr = an_get_v6addr_from_names(nbr->domain_id, 
                                                  nbr->device_id);
    ntp_peer.ifhdl = an_source_if;
    (void)an_ntp_remove_peer(&ntp_peer);
}

void 
an_event_remove_and_free_nbr (an_nbr_t *nbr)
{
     if (an_nbr_link_db_is_empty(nbr))
     {
         //If all the interfaces to this nbr are down- expire the nbr entry
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                      "\n%sNbr [%s] Link DB is empty, triggering "
                      "nbr delete", an_nd_event, nbr->udi.data);
         an_nbr_remove_and_free_nbr(nbr);
     }
}

void
an_event_nbr_link_cleanup_timer_expired (an_nbr_link_context_t *nbr_link_ctx)
{
     if (nbr_link_ctx == NULL)
     {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sCleanup timer context is NULL", an_nd_event);  
        return;
     }
    
     DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                  "\n%sNbr per link cleanup timer Expired", an_nd_event);
     an_event_nbr_link_lost(nbr_link_ctx->nbr, nbr_link_ctx->nbr_link_data);
     an_event_remove_and_free_nbr(nbr_link_ctx->nbr);

     //free the context - allocated when per link cleanup timer was initialized
     an_free_guard(nbr_link_ctx);

}

void
an_event_nbr_inside_domain (an_nbr_t *nbr) 
{
    an_cert_t domain_cert = {};
    an_if_t nbr_ifhndl = 0;
    
    if (!nbr || !nbr->device_id || !nbr->domain_id) {
        return;
    }

    if (!an_nbr_get_addr_and_ifs(nbr, NULL, &nbr_ifhndl, NULL)) {
        return;
    }

    an_get_domain_cert(&domain_cert);
    
    an_syslog(AN_SYSLOG_NBR_IN_DOMAIN,
             nbr->udi.data,an_if_get_name(nbr_ifhndl),
             an_get_domain_id(),an_get_device_id());

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sNbr [%s] is inside domain, create AN Control Plane", 
                 an_nd_event, nbr->udi.data);
    if (domain_cert.len && domain_cert.data) {

        an_bs_set_nbr_joined_domain(nbr);
        an_acp_create_to_nbr_for_all_valid_nbr_links(nbr);
        //an_acp_create_ipsec_to_nbr_for_all_valid_nbr_links(nbr);
        //topo_nbr_update(nbr, TOPO_EVENT_UP);
    }
}

void
an_event_nbr_outside_domain (an_nbr_t *nbr) 
{
    if (!nbr) {
        return;
    }
   
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sNbr [%s] is out of domain", an_nd_event, nbr->udi.data);

    if (an_acp_is_up_on_nbr(nbr)) {
        an_acp_remove_ipsec_to_nbr_for_all_valid_nbr_links(nbr);
        an_acp_remove_to_nbr_for_all_valid_nbr_links(nbr);
    }
    an_bs_init_nbr_bootstrap(nbr);
}

void
an_event_nbr_add (an_nbr_t *nbr)
{
    an_if_t nbr_ifhndl = 0;

    if (!nbr || !nbr->udi.data) {
        return;
    }

    if (!an_nbr_get_addr_and_ifs(nbr, NULL, &nbr_ifhndl, NULL)) {
        return;
    }

    an_syslog(AN_SYSLOG_NBR_ADDED,
             nbr->udi.data,an_if_get_name(nbr_ifhndl));

    an_nbr_refresh_hello();

    an_ni_cert_request(nbr);
}

an_walk_e
an_bs_init_nbr_bootstrap_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;

    if (!nbr) {
        return (AN_WALK_FAIL);
    }

    an_bs_init_nbr_bootstrap(nbr);
    return (AN_WALK_SUCCESS);
}

void 
an_event_nbr_domain_cert_validated (an_nbr_t *nbr, boolean result)
{
    an_if_t nbr_ifhndl = 0;
    an_list_element_t *elem = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    an_ntp_peer_param_t ntp_peer;

    if (!nbr) {
        return;
    }

    if (!an_nbr_get_addr_and_ifs(nbr, NULL, &nbr_ifhndl, NULL)) {
        return;
    }

    if(result == TRUE)  {
        an_syslog(AN_SYSLOG_NBR_DOMAIN_CERT_VALID,
                  nbr->udi.data,an_if_get_name(nbr_ifhndl));   
    }else   {
        an_syslog(AN_SYSLOG_NBR_DOMAIN_CERT_INVALID,
                  nbr->udi.data,an_if_get_name(nbr_ifhndl));   
    }

    if (nbr->validation.result == AN_CERT_VALIDITY_EXPIRED) {
        AN_FOR_ALL_DATA_IN_LIST(nbr->an_nbr_link_list, elem, nbr_link_data) {
            if (nbr_link_data != NULL) {
                ntp_peer.peer_addr = nbr_link_data->ipaddr;
                ntp_peer.ifhdl = nbr_link_data->local_ifhndl;
                (void)an_ntp_set_peer(&ntp_peer);
            }
        }
    }
}

void
an_event_device_bootstrapped (void)
{
    an_udi_t my_udi = {};

    if (!an_get_udi(&my_udi)) {
        return;
    }
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
           "\n%sDevice[%s] getting bootstrapped", an_bs_event, my_udi.data); 

    an_syslog(AN_SYSLOG_DEVICE_BOOTSTRAPPED, my_udi.data, an_get_domain_id());


    an_acp_init();
}

void
an_event_anra_up_locally (void)
{
    boolean ntp_status = TRUE;
    
    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAN Registrar is Locally UP, walking the Nbr DB to "
                 "initialize the Nbr bootstrap", an_ra_event);
    an_nbr_db_walk(an_bs_init_nbr_bootstrap_cb, NULL);

    if (TRUE ==  an_anra_is_live()) {
        ntp_status = an_ntp_add_remove_master(AN_NTP_MASTER_STRATUM, FALSE);
        if (TRUE == ntp_status) {
        } else {
        }

        an_mdns_anra_service_add(an_anra_get_registrar_ip(), an_source_if, NULL);
        an_set_anra_ip(an_anra_get_registrar_ip());
    }

}

void
an_event_anra_shut (void)
{
    (void)an_ntp_add_remove_master(AN_NTP_MASTER_STRATUM, TRUE);
}

void
an_event_anra_reachable (void)
{
    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAN Registrar is reachable now, walk the Nbr DB to "
                 "initiate Nbr bootstrap", an_ra_event);
    
    //topo_disc_adv();
    an_nbr_db_walk(an_bs_init_nbr_bootstrap_cb, NULL);
}

void
an_event_domain_ca_cert_learnt (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sDomain CA Certificate learnt", an_bs_event);
}

void
an_event_domain_device_cert_learnt (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sDomain Device Certficate learnt", an_bs_event); 

    an_nbr_refresh_hello();

    an_ni_validate_nbrs();
}

void
an_event_nbr_params_changed (an_nbr_t *nbr, an_msg_interest_e changed)
{
    if (!nbr || !changed) {
        return;
    }

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sNbr params", an_nd_event)
    if (AN_CHECK_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_ID) ||
        AN_CHECK_BIT_FLAGS(changed, AN_MSG_INT_DOMAIN_ID)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     " %s%s  changed, trigger cert request to Nbr [%s]", 
                     AN_CHECK_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_ID) ? 
                     "[device_id]" : "", 
                     AN_CHECK_BIT_FLAGS(changed, AN_MSG_INT_DOMAIN_ID) ?
                     ", [domain_id]" : "", nbr->udi.data);
                     
        an_ni_cert_request(nbr);
    }
}

void
an_event_nbr_refreshed (an_nbr_t *nbr)
{
    if (!nbr || !nbr->udi.data) {
        return;
    }
    
    if (an_ni_is_nbr_outside(nbr)) {
        an_bs_init_nbr_bootstrap(nbr);  
    }
}

void
an_event_acp_to_nbr_created (an_nbr_t *nbr)
{
    if (!nbr || !nbr->udi.len) {
        return;
    }

    an_acp_enable_clock_sync(nbr);
    an_acp_ntp_peer_remove_global(nbr);
}

void
an_event_acp_to_nbr_removed (an_nbr_t *nbr)
{
    an_if_t nbr_ifhndl = 0;

    if (!an_nbr_get_addr_and_ifs(nbr, NULL, &nbr_ifhndl, NULL)) {
        return;
    }

    an_syslog(AN_SYSLOG_ACP_CHANNEL_TO_NBR_REMOVED,
                            an_if_get_name(nbr_ifhndl),
                            nbr->udi.data);
}

void 
an_event_acp_negotiate_security_with_nbr_link (an_nbr_t *nbr, 
                                              an_nbr_link_spec_t *nbr_link_data)
{
}


void
an_event_if_autonomic_enable (an_if_t ifhndl)
{
    an_if_info_t *an_if_info = NULL;

    an_if_info = an_if_info_db_search(ifhndl, FALSE); 
    if (!an_if_info) {
       return;
    }

    if (an_if_info->an_if_acp_info.ext_conn_state == AN_EXT_CONNECT_STATE_HOLD) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sACP Init external connection", an_bs_event);
        an_acp_init_external_connection(ifhndl);
    }
   
    an_nd_startorstop(ifhndl);
}


void
an_event_if_autonomic_disable (an_if_t ifhndl)
{
    an_if_info_t *an_if_info = NULL;

    an_if_info = an_if_info_db_search(ifhndl, FALSE);
    if (!an_if_info) {
       return;
    }

    if (an_if_info->an_if_acp_info.ext_conn_state == AN_EXT_CONNECT_STATE_DONE) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sACP hold external connection", an_bs_event);
        an_acp_hold_external_connection(ifhndl);
    }
    
    an_nbr_db_walk(an_nbr_walk_link_lost_cb, &ifhndl);
}

void
an_event_acp_initialized (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAAA/Syslog services initialized", an_bs_event);

    an_syslog_connect();

    return;
}

void
an_event_acp_pre_uninitialization (void)
{
    /*Syslog*/  
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sSyslog uninitialized", an_bs_event);
    an_syslog_disconnect();
    return;
}

void
an_event_acp_uninitialized (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAutonomic Control Plane Uninitialized", an_bs_event);
    return;
}

void
an_event_clock_synchronized (void)
{
    an_ntp_do_calendar_update();
    an_ni_validate_nbrs();
}


void
an_event_generic_timer_expired (void)
{

    an_addr_t anr_ip = AN_ADDR_ZERO;
    if (an_anra_is_live() && an_acp_is_initialized()) {
        anr_ip = an_anra_get_registrar_ip();
        an_mdns_anra_service_add(anr_ip, an_source_if, NULL);
    }

    an_timer_start(&an_generictimer, AN_GENERIC_TIMER_INTERVAL);    
    return;
}
