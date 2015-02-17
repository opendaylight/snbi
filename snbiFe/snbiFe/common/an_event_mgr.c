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
#include "../al/an_syslog.h"
#include "an_nd.h"
#include "an_ni.h"
#include "an_bs.h"
#include "an_nbr_db.h"
#include "an_anra.h"
#include "an_anra_db.h"
#include "an_if_mgr.h"
#include "an_acp.h"
#include "an.h"
#include "an_event_mgr.h"
//#include "an_topo_disc.h"
#include "../al/an_sudi.h"
#include "../al/an_aaa.h"
#include "../al/an_mem.h"
#include "../al/an_ntp.h"
#include "../al/an_cert.h"
//#include "../ios/an_l2.h"
#include "../al/an_str.h"
#include "../al/an_syslog.h"
//#include "../ios/an_service_discovery.h"
//#include "../ios/an_parse_ios.h"
#include "../al/an_cert.h"
#include "an_event_mgr.h"
#include "../al/an_timer.h"

extern void an_detach_from_environment(void);
extern void an_attach_to_environment(void);
extern void an_parser_init(void);
extern an_avl_tree an_mem_elem_tree;

an_timer an_generictimer = {0};
an_timer an_revoke_check_timer = {0};
an_timer an_my_cert_renew_expire_timer = {0};
an_unix_time_t my_5perc_poll_timer = 0;
an_unix_time_t my_1perc_poll_timer = 0;
an_timer an_anra_bs_thyself_retry_timer = {0};

an_unix_time_t an_crl_expire_interval = 0;

extern an_mem_chunkpool_t *an_address_saved_context_pool;
extern an_mem_chunkpool_t *an_aaa_saved_context_pool;
extern uint32_t an_cd_untagged_refresh_expire_cnt;
extern boolean an_intent_parse_file_after_system_configured;
extern boolean an_intent_stale_cleanup_required;
extern uint32_t an_intent_stale_cleanup_wait_cnt;

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

    if (an_if_is_tunnel(ifhndl)) {
        DEBUG_AN_LOG(AN_LOG_INTENT_EVENT, AN_DEBUG_MODERATE, NULL, 
                    "\nAN: INTENT - interface %s is up, flooding intent version",
                    an_if_get_name(ifhndl));
    }
    
    /*
     * On autonomically created or configured interfaces start Adjacency discovery
     */
    if ((an_if_info->autonomically_created) ||
        (AN_ND_CFG_ENABLED == an_nd_state_get(ifhndl))) { 
        an_event_interface_activated(an_if_info);
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
an_event_clean_and_refresh_nbr_cert (an_nbr_t *nbr)
{
    if (!nbr) {
      return;
    }
    /*Stop Nbr cert related timer*/ 
    an_timer_stop(&nbr->cert_request_timer);
    an_timer_stop(&nbr->cert_revalidate_timer);
    an_timer_stop(&nbr->cert_expire_timer);
    
    nbr->renew_cert_poll_count = 0;
    nbr->my_cert_expired_time = 0;
    nbr->renew_cert_5perc_poll_timer = 0;
    nbr->renew_cert_1perc_poll_timer = 0;
    nbr->validation.result = AN_CERT_VALIDITY_UNKNOWN;

    /*Clean up domain cert*/
    if (nbr->domain_cert.data) {
        an_free_guard(nbr->domain_cert.data);
    }
    nbr->domain_cert.data = NULL;
    nbr->domain_cert.len = 0;
    
    an_timer_start(&nbr->cert_expire_timer,
                   AN_NBR_CERT_IMPORT_BUFFER_TIME_SEC*1000);
    
}


void
an_event_clean_expired_device (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
             "\n%sClean up expired device for new bootstrap", an_bs_event);

    /*Stop all BS related timers on the expired device*/

    //Do not stop my cert expire timer- when u receive new certificate stop it
    an_timer_stop(&an_anra_bs_thyself_retry_timer);
    an_timer_stop(&an_revoke_check_timer);
    an_crl_expire_interval = 0;

    //TBD: Stop services before bring down ACP    
    //Stop config download, service discovery, aaa
    
    /* Reset ACP */
    an_acp_uninit();
   
    /*Clear dbs*/ 
    an_acp_client_db_init();          
}

void
an_event_autonomics_uninit (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAutonomic uninit", an_nd_event);
    //Disable AN modules
    an_sudi_uninit();
    //topo_disc_uninit(); 
    an_bs_uninit();

    //Stop services before bring down ACP    
    an_sd_cfg_global_commands(FALSE);

    /* Reset ACP */
    an_acp_uninit();
    an_aaa_set_new_model(FALSE);
 
    /* Reset ND */
    an_nd_uninit();
    an_if_uninit();

    an_clear_service_info_db();

    /* Final Global Reset */
    an_reset_global_info();
    an_set_device_enrollment_url(FALSE);

    /* AN DBs Clear */
    an_nbr_db_init();
    an_acp_client_db_init();          
    
    an_platform_specific_uninit();
    an_avl_uninit(&an_mem_elem_tree);

    /*Stop all timers on device*/
    an_timer_stop(&an_anra_bs_thyself_retry_timer);
    an_timer_stop(&an_my_cert_renew_expire_timer);
    an_timer_stop(&an_generictimer);
    an_timer_stop(&an_revoke_check_timer);

    an_crl_expire_interval = 0;
}    

void
an_event_autonomics_init (void)
{
    /* Infra enable for AN */
    an_log_init();      
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAutonomic init", an_nd_event);

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
    an_timer_init(&an_revoke_check_timer, AN_TIMER_TYPE_CHECK_CERT_REVOKE, NULL, FALSE);
    an_timer_init(&an_generictimer, AN_TIMER_TYPE_GENERIC, NULL, FALSE);
    an_timer_init(&an_my_cert_renew_expire_timer, AN_TIMER_TYPE_MY_CERT_EXPIRE,
                   NULL, FALSE);
    an_timer_init(&an_anra_bs_thyself_retry_timer, 
                  AN_TIMER_TYPE_ANRA_BS_THYSELF_RETRY, NULL, FALSE);
    if (an_system_is_configured()) {
        an_platform_specific_init();
        an_sudi_init();
    }
}

void
an_event_registrar_init (void)
{
    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sRegistrar init", an_ra_event);

    an_log_init();
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
    if (an_is_global_cfg_autonomic_enabled()) {
        an_sudi_init();
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

    an_syslog(AN_SYSLOG_UDI_AVAILABLE, my_udi.data);
    if (an_create_trustpoint("MASACRT", "nvram:masa_crt.pem")) {
        an_log(AN_LOG_MASA | AN_LOG_EVENT, 
               "\nAN: Event - Created MASA trustpoint");
    } else {
        an_log(AN_LOG_MASA | AN_LOG_EVENT, 
               "\nAN: Event - Failed to create MASA trustpoint");
    }

    an_if_init();

    /* uninit ND first, so that any ND using UDI is removed */
    if (an_is_global_cfg_autonomic_enabled()) {

        an_syslog_create_an_discriminator();
        an_nd_uninit();
        an_nd_init();
    }

//    an_cert_pki_crl_cleanup(); 
    an_timer_start(&an_generictimer, AN_GENERIC_TIMER_INTERVAL);
    if (an_is_active_rp()) {
        an_bs_retrieve_saved_enrollment();
    }
    
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

    an_if_init();

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
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sCert Req timer reset for nbr [%s]", 
                 an_bs_event, nbr->udi.data);

    an_ni_cert_request_retry(nbr);
}

void
an_event_hello_refresh_timer_expired (void)
{
    an_nbr_refresh_hello();
}

void
an_event_interface_activated (an_if_info_t *an_if_info)
{
    if (an_nd_is_operating(an_if_info->ifhndl)) {
        return;
    }

    an_nd_start_on_interface(an_if_info->ifhndl);
    return;        
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
    return;
}

void
an_event_nbr_link_lost (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    an_ntp_peer_param_t ntp_peer = {{0}};

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
    ntp_peer.peer_addr = nbr_link_data->ipaddr;
    ntp_peer.ifhdl = nbr_link_data->local_ifhndl;
    (void)an_ntp_remove_peer(&ntp_peer, TRUE);

    if (an_acp_is_up_on_nbr_link(nbr_link_data)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sRemoving AN Control Plane on the Nbr[%s] link [%s]", 
                     an_nd_event, nbr->udi.data, 
                     an_if_get_name(nbr_link_data->local_ifhndl));
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
    an_ntp_peer_param_t ntp_peer = {{0}};
    if_data = (an_nbr_link_context_t *) context;

    if (current == NULL || if_data == NULL)    {
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    curr_data = (an_nbr_link_spec_t *) current->data;
    
    an_syslog(AN_SYSLOG_NBR_LOST,
              if_data->nbr->udi.data, 
              an_if_get_name(curr_data->local_ifhndl));

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_INFO, NULL, 
                 "\n%sNbr Link lost interface %s", an_nd_event, 
                 an_if_get_name(curr_data->local_ifhndl));
    ntp_peer.peer_addr = curr_data->ipaddr;
    ntp_peer.ifhdl = curr_data->local_ifhndl;
    (void)an_ntp_remove_peer(&ntp_peer, TRUE);

    if (an_acp_is_up_on_nbr_link(curr_data)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_INFO, NULL,
                     "\n%sRemoving AN control plane on link %s",
                     an_nd_event,
                     an_if_get_name(curr_data->local_ifhndl));
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
    an_nbr_link_context_t nbr_link;
    an_cerrno ret;
   
    if (!nbr) {
      return;
    }
   
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sNbr [%s] lost", an_nd_event, nbr->udi.data);

    nbr_link.nbr_link_data = &nbr_link_data;
    nbr_link.nbr = nbr;
    ret = an_nbr_link_db_walk(nbr->an_nbr_link_list, 
                              an_event_nbr_link_lost_cb,
                              &nbr_link);

    /* Delete ntp peer over acp */
    an_acp_remove_clock_sync_with_nbr(nbr);    
}

void 
an_event_remove_and_free_nbr (an_nbr_t *nbr)
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
an_event_nbr_link_cleanup_timer_expired (an_nbr_link_context_t *nbr_link_ctx)
{
     if (nbr_link_ctx == NULL)
     {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL, 
                     "\n%sCleanup timer context is NULL", an_nd_event);  
        return;
     }
    
     DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_INFO, NULL,
                  "\n%sNbr per link cleanup timer Expired", an_nd_event);
     an_event_nbr_link_lost(nbr_link_ctx->nbr, nbr_link_ctx->nbr_link_data);
     an_event_remove_and_free_nbr(nbr_link_ctx->nbr);

     //free the context - allocated when per link cleanup timer was init
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
             nbr->udi.data, an_if_get_name(nbr_ifhndl),
             an_get_domain_id(), an_get_device_id());

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

an_avl_walk_e
an_bs_init_nbr_bootstrap_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;

    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }

    an_bs_init_nbr_bootstrap(nbr);
    return (AN_AVL_WALK_SUCCESS);
}

void 
an_event_nbr_domain_cert_validated (an_nbr_t *nbr)
{
    if (nbr->validation.result == AN_CERT_VALIDITY_PASSED) {
        an_ni_start_nbr_cert_expire_timer(nbr);
    }
}

void
an_event_start_my_cert_expire_timer (void)
{
    an_cert_api_ret_enum result;
    an_unix_msec_time_t cert_validity_interval = 0;
    an_unix_msec_time_t new_cert_validity_interval = 0;
    an_unix_time_t validity_time;
    an_cert_t domain_cert = {};
    int16_t shadow_percentage = 0;
    an_unix_msec_time_t perc_75 = 0;
    an_unix_time_t perc_5 = 0;
    an_unix_time_t perc_1 = 0;
    an_unix_time_t perc_40 = 0;
    uint8_t validity_time_str[TIME_DIFF_STR];
    an_unix_time_t  expiry_time = 0;

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
          "\nIn start my cert expire timer", an_bs_event);

    an_get_domain_cert(&domain_cert);
    if (domain_cert.data && domain_cert.len) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
          "\nGet domain cert success", an_bs_event);
        
        result = an_cert_get_cert_expire_time(&domain_cert, 
                                   &cert_validity_interval, &validity_time);    
        if (result != AN_CERT_API_SUCCESS) {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL, 
                 "\n%sUnable to get device cert expire time", an_bs_event);
            return;
        } 
        an_unix_time_timestamp_conversion(validity_time, 
                                          validity_time_str);
        shadow_percentage = an_cert_get_auto_enroll_perc();
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
          "\n%sGet domain cert validity interval %lld msec, "
          "shadow percentage %d", an_bs_event, 
          cert_validity_interval, shadow_percentage);
        
        an_cert_compute_cert_lifetime_percent(cert_validity_interval, 
                                  &perc_5, &perc_1, &perc_40, &perc_75);
        my_5perc_poll_timer = perc_5;
        my_1perc_poll_timer = perc_1;

        result = an_cert_get_crl_expiry_time(&domain_cert, &expiry_time);
        if (result == AN_CERT_API_SUCCESS && expiry_time > 0) {            

            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
              "\n%sFrom API crl revoke timer %ld", an_bs_event, expiry_time);

            an_crl_expire_interval = expiry_time * 1000;   

        } else {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
              "\n%sSet crl revoke timer to 40 perc of cert lifetime %ld", 
              an_bs_event, perc_40);
            an_crl_expire_interval = perc_40;
        }

        if (shadow_percentage > 0 && cert_validity_interval > 0) {
            new_cert_validity_interval = 
                (longlong) ((cert_validity_interval * 
                            (longlong) shadow_percentage)/(longlong) 100);
        }

        if (new_cert_validity_interval > 0) {   
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                "\n%sStarted my cert expiry timer- %lld msec "
                "Cert End LifeTime %s", an_bs_event,               
                new_cert_validity_interval,
                validity_time_str);
            an_timer_start64(&an_my_cert_renew_expire_timer, 
                             new_cert_validity_interval);
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
           "\n%sDevice [%s] getting bootstrapped", an_bs_event, my_udi.data); 

    an_syslog(AN_SYSLOG_DEVICE_BOOTSTRAPPED, my_udi.data, an_get_domain_id());

    an_acp_init();

    an_nbr_refresh_hello();

    an_ni_validate_nbrs();
    
    if (an_timer_is_running(&an_my_cert_renew_expire_timer)) {
        an_timer_stop(&an_my_cert_renew_expire_timer);
    }
    an_event_start_my_cert_expire_timer();
    an_event_start_revoke_check_timer();
    an_cert_config_crl_auto_download(AN_CERT_CRL_PREPUBLISH_INTERVAL);
}

void 
an_event_device_cert_enroll_success (uchar *cert_der,
                uint16_t cert_len, an_udi_t dest_udi,
                an_addr_t proxy_device, an_iptable_t iptable)
{
    an_cert_t device_cert = {};
    int indicator = 0;
 
    if (!cert_der) {
        return;
    }
    an_memcmp_s(dest_udi.data, AN_UDI_MAX_LEN, "enroll-test", 
                an_strlen("enroll-test"), &indicator);
    if (!indicator) {
        //This is executed from test cli
        an_cert_displaycert_in_pem(cert_der, cert_len);
        return;
    }

    boolean anra_state = an_anra_is_live();
    boolean an_state = an_is_global_cfg_autonomic_enabled();

    if (!an_state || !anra_state) {
        //Check if autonomic is disaled or ANRA is NOT live
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL, 
                     "\n%sFreeing Enroll response as "
                     "ANRA state %d, AN enabled %d", an_bs_event, 
                     anra_state, an_state);
        return;
    }
    device_cert.len = cert_len;
    device_cert.valid = TRUE;
    device_cert.data = (uint8_t *)an_malloc_guard(cert_len, "AN Cert Grant");
    if (!device_cert.data) {
        return;
    }
    device_cert.valid = TRUE;
    an_memcpy_guard_s(device_cert.data, device_cert.len, cert_der, cert_len);
    an_anra_notify_cert_enrollment_done(&device_cert, dest_udi, 
                                        proxy_device, iptable);

    //Free the malloced memory as it is copied into bs_response packet
    if (device_cert.data) {
        an_free_guard(device_cert.data);
    }
}

void
an_event_device_cert_enroll_failed (void)
{
    //Only for ANRA try repeated bootstrap- for other devices- Repeated 
    //Nbr connect will take care of enrollment
    if (an_anra_is_device_ra_and_not_bootstraped()) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                "\n%sTry ANRA bootstrap thyself after some time- start timer", 
                an_bs_event);
        an_timer_start(&an_anra_bs_thyself_retry_timer, 
                       AN_ANRA_BS_THYSELF_RETRY_INTERVAL);
    }
}

void
an_event_anra_bootstrap_retry_timer_expired (void)
{    
   DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                "\n%sANRA bootstrap thyself timer Expired", an_bs_event);
   an_anra_bootstrap_thyself();
}

void
an_event_anra_up_locally (void)
{
    boolean ntp_status = TRUE;
    an_anr_param_t anr_param = {{0}};
    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
             "\n%sAutonomic Registrar is Locally UP, walking the Nbr DB to "
             "initialize the Nbr bootstrap", an_ra_event);
    an_nbr_db_walk(an_bs_init_nbr_bootstrap_cb, NULL);
    an_cert_config_crl_auto_download(AN_CERT_ANRA_CRL_PREPUBLISH_INTERVAL);

    if (TRUE ==  an_anra_is_live()) {
        an_nbr_db_walk(an_acp_remove_clock_sync_with_nbrs, NULL);
        an_acp_remove_clock_sync_with_server(g_ntp_ra_address);
		ntp_status = an_ntp_add_remove_master(AN_NTP_MASTER_STRATUM, 
											  FALSE);
		if (TRUE == ntp_status) {
			DEBUG_AN_LOG(AN_LOG_SRVC_NTP,  AN_DEBUG_MODERATE, NULL, 
						 "\n%sNTP enabled locally", an_srvc_ntp);
		} else {
			DEBUG_AN_LOG(AN_LOG_SRVC_NTP,  AN_DEBUG_MODERATE, NULL,
						 "\n%sFailed to enable NTP locally", 
						 an_srvc_ntp);
		}
        an_sd_cfg_if_commands(an_source_if, TRUE);
        /* TODO call an_service_announce() function with proper parameters*/
        anr_param.ca_type = (uint8_t *)an_malloc(
                            an_strlen(an_anra_get_ca_type_name()) + 1, "CA type name");
        if (NULL == anr_param.ca_type) {
            return;
        }

        an_strcpy(anr_param.ca_type, AN_CA_SERVER_LEN, an_anra_get_ca_type_name());
        an_free(anr_param.ca_type);
        an_set_anra_ip(an_anra_get_registrar_ip());
    }

}

void
an_event_anra_shut (void)
{
	(void)an_ntp_add_remove_master(AN_NTP_MASTER_STRATUM, TRUE);

    an_acp_start_ntp_with_nbrs();
}

void
an_event_anra_reachable (void)
{
    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_INFO, NULL,
             "\n%sAutonomic Registrar is reachable now, walk the Nbr DB to "
             "initiate Nbr bootstrap", an_ra_event);
    
    //topo_disc_adv();
    an_nbr_db_walk(an_bs_init_nbr_bootstrap_cb, NULL);
}

void
an_event_domain_ca_cert_learnt (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL, 
                 "\n%sDomain CA Certificate learnt", an_bs_event);
}

void
an_event_domain_device_cert_renewd (void)
{
    an_udi_t my_udi = {0};

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
               "\n%sDomain Device Certficate has been renewed", an_bs_event);    

    if (!an_get_udi(&my_udi))  {
        return;
    }

    if (my_udi.data && my_udi.len) {
        an_syslog(AN_SYSLOG_MY_DOMAIN_CERT_RENEWED, my_udi.data);   
    }
    an_event_start_my_cert_expire_timer();
    an_event_start_revoke_check_timer();
    return;
}

void
an_event_domain_device_cert_expired (void)
{
    an_udi_t my_udi = {0};

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
            "\n%sDomain Device Certificate has expired", an_bs_event);    

    if (!an_get_udi(&my_udi))  {
        return;
    }

    if (my_udi.data && my_udi.len) {
        an_syslog(AN_SYSLOG_MY_DOMAIN_CERT_EXPIRED, my_udi.data);   
    }
    an_event_clean_expired_device();
    if (an_anra_is_configured() && an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
            "\n%sANRA trying to bootstrap itself", an_bs_event);    
        an_anra_bootstrap_thyself();
    }

    return;
}

void
an_event_start_revoke_check_timer (void)
{    
    if (an_timer_is_running(&an_revoke_check_timer)) {
        an_timer_stop(&an_revoke_check_timer);
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
          "\n%sStart revocation check timer %ld msec", 
          an_bs_event, an_crl_expire_interval);

    //Revoke check timer =  read from CRL lifetime given in the certificate
    if (an_crl_expire_interval > 0) {
        an_timer_start(&an_revoke_check_timer, 
                       an_crl_expire_interval);
    }
}

void
an_event_restart_revoke_check_timer (an_unix_time_t revoke_interval)
{    
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
          "\n%sRestart revocation check timer %ld msec", 
          an_bs_event, revoke_interval);

    //Revoke check timer =  read from CRL lifetime given in the certificate
    if (revoke_interval > 0) {
        an_timer_start(&an_revoke_check_timer, 
                       revoke_interval);
    }
}

void 
an_event_set_revoke_timer_interval (uint16_t interval_in_mins)
{    
    if (interval_in_mins >= 10) {
        //convert the mins to msecs
        an_crl_expire_interval = interval_in_mins * 60 * 1000;
    }else { //use the default value
        an_crl_expire_interval =  AN_REVOKE_CHECK_TIMER_INTERVAL;
    }
    printf("\nRevoke check timer interval set from test cli %ld (msec)",
                an_crl_expire_interval);

}
     
void
an_event_domain_device_cert_learnt (void)
{

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sDomain Device Certficate learnt", an_bs_event); 
   
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
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_INFO, NULL,
                     " %s%s  changed, trigger cert request to Nbr [%s]", 
                     AN_CHECK_BIT_FLAGS(changed, AN_MSG_INT_DEVICE_ID) ? 
                     "[device_id]" : "", 
                     AN_CHECK_BIT_FLAGS(changed, AN_MSG_INT_DOMAIN_ID) ?
                     ", [domain_id]" : "", nbr->udi.data);
                     
        an_ni_cert_request(nbr);
    }
}

void
an_event_nbr_refreshed (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    an_if_t tunn_ifhndl;
    an_if_t tunn_src_ifhndl;
    
    if (!nbr || !nbr->udi.data) {
        return;
    }
    
    if (!an_ni_is_nbr_inside(nbr)) { 
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                     "\n%sNbr refreshed and is outside domain, "
                     "hence going to bootstrap Nbr [%s]", 
                     an_bs_pak, nbr->udi.data);
        an_bs_init_nbr_bootstrap(nbr);  
    }

    if (!nbr_link_data) {
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
    }
}

void
an_event_acp_on_nbr_link_created (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    an_if_t ifhndl = 0;
    if (!nbr || !nbr->udi.len || !nbr_link_data){
        return;
    }

    an_acp_enable_clock_sync_with_nbr(nbr);
    an_acp_ntp_peer_remove_global(nbr);

    ifhndl = an_acp_get_acp_if_on_nbr_link(nbr, nbr_link_data);
    /* Enable service discovery on interface */
    if (ifhndl) {
        an_sd_cfg_if_commands(ifhndl, TRUE);
        an_discover_services(ifhndl);
    }
}

void
an_event_acp_on_nbr_link_removed (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    an_if_t nbr_ifhndl = 0;
    an_if_t ifhndl = 0;

    if (!nbr || !nbr_link_data) {
        return;
    }

    an_acp_remove_clock_sync_with_nbr(nbr);
    ifhndl = an_acp_get_acp_if_on_nbr_link(nbr, nbr_link_data);
    if (ifhndl) {
        an_discover_services_stop(ifhndl);
        an_sd_cfg_if_commands(ifhndl, FALSE);
    }

    if (!an_nbr_get_addr_and_ifs(nbr, NULL, &nbr_ifhndl, NULL)) {
        return;
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sAN Control Plane to Nbr [%s] is removed", 
                 an_bs_event, nbr->udi.data);
}


void
an_event_if_autonomic_enable (an_if_t ifhndl)
{
    an_if_info_t *an_if_info = NULL;
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
    printf("\n ***Inside func an_event_if_autonomic_enable, starting CD/ND on interface");
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

    if (an_if_info->an_if_acp_info.ext_conn_state == 
                AN_EXT_CONNECT_STATE_DONE) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sACP hold external connection", an_bs_event);
        an_acp_hold_external_connection(ifhndl);
    }
    an_nbr_db_walk(an_nbr_walk_link_lost_cb, &ifhndl);
}

void
an_event_acp_initialized (void)
{
    an_cert_api_ret_enum result;
    an_addr_t anra_ip = AN_ADDR_ZERO;

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAAA/Syslog services initialized", an_bs_event);

    an_syslog_connect();
    if (an_anra_is_configured()) { 
        anra_ip = an_anra_get_registrar_ip();
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sConfig in tp ANRA ip %s", 
                  an_bs_event, an_addr_get_string(&anra_ip));
        result = an_cert_config_trustpoint(anra_ip);
    } else {
        result = an_cert_config_trustpoint(an_get_anra_ip());
    }
    if (result != AN_CERT_API_SUCCESS)
    {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                 "\n%sError in configuring Re-enrollment params on "
                 "trustpoint %s", an_bs_event, AN_DOMAIN_TP_LABEL);
    }

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
    DEBUG_AN_LOG(AN_LOG_SRVC_NTP, AN_DEBUG_MODERATE, NULL, 
                 "\n%sClock got synchronized", an_srvc_ntp);
    an_ntp_do_calendar_update();
    an_ni_validate_expired_nbrs();
}

void
an_event_generic_timer_expired (void)
{
    an_addr_t anr_ip = AN_ADDR_ZERO;
    an_anr_param_t anr_param = {{0}};
    if (an_anra_is_live() && an_acp_is_initialized()) {
        anr_ip = an_anra_get_registrar_ip();
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
               "\n%sGeneric timer expired. Adding Autonomic Registrar "
               "address [%s] to mdns cache",
                an_srvc_event, an_addr_get_string(&anr_ip));

        /* TODO call an_service_announce()*/
        anr_param.ca_type = an_malloc(an_strlen(an_anra_get_ca_type_name()) + 1, "CA type name");
        if (NULL == anr_param.ca_type) {
            return;
        }

        an_strcpy(anr_param.ca_type, AN_CA_SERVER_LEN, an_anra_get_ca_type_name());
        an_free(anr_param.ca_type);
    }

    an_timer_start(&an_generictimer, AN_GENERIC_TIMER_INTERVAL);    
    return;
}

void 
an_event_nbr_domain_cert_expired (an_nbr_t *nbr)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
             "\n%sNbr %s device cert is expired", an_bs_event, nbr->udi.data);
    an_ni_set_state(nbr, AN_NI_CERT_EXPIRED);
    an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_EXPIRED);
    an_event_clean_and_refresh_nbr_cert(nbr);
}
                
void 
an_event_nbr_domain_cert_revoked (an_nbr_t *nbr)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
             "\n%sNbr %s device cert is revoked", an_bs_event, nbr->udi.data);
    an_ni_set_state(nbr, AN_NI_OUTSIDE);
    an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_REVOKED);
}

void
an_event_nbr_cert_in_validity_expired_state (an_nbr_t *nbr)
{
    an_list_element_t *elem = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    an_ntp_peer_param_t ntp_peer = {{0}};

    if (!nbr) {
        return;
    }
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
       "\n%sNBR cert expired, starting clock sync ", an_bs_event);

    AN_FOR_ALL_DATA_IN_LIST(nbr->an_nbr_link_list, elem, 
                    nbr_link_data) {
        if (nbr_link_data != NULL) {
           DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
              "\n%sBoot Strapping: %s clock sync with nbr %s",
              nbr->udi.data);
            ntp_peer.peer_addr = nbr_link_data->ipaddr;
            ntp_peer.ifhdl = nbr_link_data->local_ifhndl;
            (void)an_ntp_set_peer(&ntp_peer, TRUE);
        }
    }
    return;
}


void
an_event_cert_revoke_check_timer_expired (void)
{
   an_unix_time_t revoke_interval = 0;
   an_cert_t domain_cert = {};
   an_cert_api_ret_enum result;

   DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
       "\n%sCertificate Revoke Check Timer expired- check cert aginst CRL",
       an_bs_event);
 
   //If trustpoint busy in renewal do not do crl based cert validation 
   // AN workaround to avoid hitting crypto bug - CRL download aborts
   // trustpoint undergoing renewal at the same time
   if (!an_cert_is_tp_busy_in_renew()) {
       an_ni_validate_with_crl_nbrs(); 
       if (an_get_domain_cert(&domain_cert)) {
           //CRL present- PKI Validate call immediately returns
           //Start revoke check timer
           if (an_cert_is_crl_present(&domain_cert)) {
               result = an_cert_get_crl_expiry_time(&domain_cert, 
                                                    &revoke_interval);
               if (result == AN_CERT_API_SUCCESS && revoke_interval > 0) {
                   revoke_interval = revoke_interval * 1000;   
                   an_event_restart_revoke_check_timer(revoke_interval);        
                   return;
               }
           } else {
               //CRL not present- PKI Validate will trigger CRL download
               //Now rerun revoke check timer after 3 mins
               DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                   "\n%sNo CRL available now, rerun Cert Validation check "
                   "cert validation", an_bs_event);
               an_event_restart_revoke_check_timer(
                    AN_CERT_WAIT_TO_RERUN_REVOKE_CHECK);        
           }           
       }
   }else {
       DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
          "\n%sAN Domain cert is being renewed- will do without CRL "
          "cert validation", an_bs_event); 
       an_ni_validate_nbrs(); 
       an_event_restart_revoke_check_timer(
                    AN_CERT_WAIT_TO_RERUN_REVOKE_CHECK);        
   }

}

void
an_event_nbr_cert_revalidate_timer_expired (an_nbr_t *nbr)
{
   DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL, 
             "\n%sCRL check returned PKI_API_VERIFY_FAILURE, "
             "cert not validated, hence revalidate Nbr certificate", 
             an_bs_event);
   an_ni_validate_with_crl(nbr);
}

void 
an_event_nbr_cert_renew_timer_expired (an_nbr_t *nbr)
{
    uint8_t now_time_str[TIME_DIFF_STR];     
    an_unix_msec_time_t now;
 
    if (!nbr) {
        return;
    }    
    now = an_unix_time_get_current_timestamp();
    an_unix_time_timestamp_conversion(now, now_time_str);

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
       "\n%sNbr cert timer expired, send NI cert fetch req, "
       " at %s", 
       an_bs_event, now_time_str);

    an_ni_cert_request(nbr);
    return;
}

void 
an_event_my_cert_renew_timer_expired (void)
{
    an_cert_t renewed_device_cert = {};
    an_cert_t old_device_cert = {};
    an_unix_time_t renew_validity_time = 0;
    an_unix_time_t old_validity_time = 0;
    an_unix_msec_time_t renew_cert_validity_interval = 0;
    an_unix_msec_time_t old_cert_validity_interval = 0;
    an_unix_msec_time_t diff_in_validity_interval = 0;
    an_cert_api_ret_enum renewed_cert_fetch_result;
    an_cert_api_ret_enum renewed_cert_get_validtime_result;
    an_cert_api_ret_enum old_cert_get_validtime_result;
   
    an_get_domain_cert(&old_device_cert);
    if (!old_device_cert.data || !old_device_cert.len) {
         return;
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
        "\n%sMy certificate expired- Will try to get renewed certificate "
        "from the trustpoint %s", an_bs_event, AN_DOMAIN_TP_LABEL);

    renewed_cert_fetch_result = 
                an_cert_get_device_cert_from_tp(AN_DOMAIN_TP_LABEL,
                                             &renewed_device_cert);
    
    if (renewed_cert_fetch_result == AN_CERT_API_SUCCESS) {
        
        renewed_cert_get_validtime_result = an_cert_get_cert_expire_time(
                        &renewed_device_cert, 
                        &renew_cert_validity_interval, &renew_validity_time);    

        old_cert_get_validtime_result = an_cert_get_cert_expire_time(
                        &old_device_cert, 
                        &old_cert_validity_interval, &old_validity_time);    
         
        if (renewed_cert_get_validtime_result == AN_CERT_API_SUCCESS && 
            old_cert_get_validtime_result == AN_CERT_API_SUCCESS) {
            
            if (old_cert_validity_interval <= renew_cert_validity_interval) {
                diff_in_validity_interval = (renew_cert_validity_interval - 
                                        old_cert_validity_interval);
            } 
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL, 
                  "\n%sRead from tp, diff in time b.w existing and new cert"
                  "from tp differ by %lld msec, old %lld msec, "
                  "renewed %lld msec",
                  an_bs_event, diff_in_validity_interval, 
                  old_cert_validity_interval,
                  renew_cert_validity_interval);
            if (diff_in_validity_interval == 0) {
                DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sRetry getting renewed cert from tp - "
                    "starting timer for %d", 
                    an_bs_event, my_5perc_poll_timer);
                an_timer_start(&an_my_cert_renew_expire_timer, my_5perc_poll_timer);            
            } else if (diff_in_validity_interval > 0) {
                //Store the new certificate in the an_info global structure
                DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL, 
                       "\n%sTrustpoint %s has renewed certificate for AN"
                       " AN device", an_bs_event,
                        AN_DOMAIN_TP_LABEL);
                an_set_domain_cert(renewed_device_cert, AN_CERT_TYPE_RENEWED);
            } //end of if - diff in time b.w old and new cert

        }//end of if - validity fetch success
    } else if (renewed_cert_fetch_result == 
               AN_CERT_EXPIRED_DEVICE_CERT_IN_TP) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
             "\n%sRead expired cert from tp", an_bs_event);
        an_event_domain_device_cert_expired();
        if (!an_anra_is_configured()) {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
             "\n%sRestart poll my cert timer on AN device", an_bs_event);
            an_timer_start(&an_my_cert_renew_expire_timer,
                           my_1perc_poll_timer);
        }
    }else {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
             "\n%sReading from tp failed, Retry getting renewed cert",
             an_bs_event);
        an_timer_start(&an_my_cert_renew_expire_timer,
                       my_5perc_poll_timer);
    } //end of if - fetch renew cert from tp
}

void
an_event_validation_cert_response_obtained (an_cert_validation_result_e status, 
                                            void *device_ctx)
{
    an_ni_validate_context_t *udi_ctx = NULL;
    an_nbr_t *nbr = NULL;

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                "\n%sCert Validation Response Callback from PKI",
                an_bs_event);
    udi_ctx = (an_ni_validate_context_t *) device_ctx;

    if (!udi_ctx || !udi_ctx->save_udi.data) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                      "\n%sGot event validation response, input param NULL",
                      an_bs_event);
        return;
    }

    nbr = an_nbr_db_search(udi_ctx->save_udi);
    
    if (udi_ctx) {
        if (udi_ctx->save_udi.data) {
            an_free_guard(udi_ctx->save_udi.data);
        }
        an_free_guard(udi_ctx);
    }

    if (!nbr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sGot validation response, but nbr udi not in Nbr db",
                    an_bs_event);
        return;
    }
    
/*    if (status == AN_CERT_VALIDITY_PASSED_WARNING &&
        nbr->validation.result == AN_CERT_VALIDITY_REVOKED) {
        //Previous nbr state - REVOKED and
        //now CRL not available - continue to mark revoked
        status = AN_CERT_VALIDITY_REVOKED;
    }

*/
    an_event_update_nbr_cert_validation_result(status, nbr);
}

void
an_event_update_nbr_cert_validation_result (an_cert_validation_result_e result, 
                        an_nbr_t *nbr)
{
    if (result == AN_CERT_VALIDITY_PASSED_WARNING) {
        if (nbr->validation.result == AN_CERT_VALIDITY_REVOKED) {
           DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNeighbor [%s] domain cert was earlier revoked"
                     " and now no CRL available to validate- keeping as revoked",
                     an_bs_event, nbr->udi.data); 
           an_event_nbr_domain_cert_revoked(nbr);
        } else {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                "\n%sNeighbor [%s] domain cert validated as passed with warning",
                 an_bs_event, nbr->udi.data); 
            an_ni_set_state(nbr, AN_NI_INSIDE);
            an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_PASSED);
        }
    } else if (result == AN_CERT_VALIDITY_PASSED) {
        if (nbr->validation.result == AN_CERT_VALIDITY_EXPIRED) {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                        "\n%sNeighbor [%s] domain cert validated "
                        "after clock sync - nbr validated as expired "
                        "earlier", an_bs_event, nbr->udi.data);
        } else {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                        "\n%sNeighbor [%s] domain cert validation success", 
                        an_bs_event, nbr->udi.data); 
        }
        an_ni_set_state(nbr, AN_NI_INSIDE);
        an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_PASSED);
    } else if (result == AN_CERT_VALIDITY_EXPIRED) {
        an_event_nbr_domain_cert_expired(nbr);
    } else if (result == AN_CERT_VALIDITY_REVOKED) {
        if (nbr->validation.result != AN_CERT_VALIDITY_EXPIRED) {
            an_event_nbr_domain_cert_revoked(nbr);
        }
    } else if (result == AN_CERT_VALIDITY_PENDING) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
            "\n%sNeighbor [%s] domain cert validation pending "
            "for revocation check", 
            an_bs_event, nbr->udi.data);
    //    an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_PENDING)
    } else if (result == AN_CERT_VALIDITY_BUSY_CRL_POLL) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
            "\n%sNeighbor [%s] domain cert validation not done"
            " - will call Cert Validate again", 
            an_bs_event, nbr->udi.data);
    //    an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_BUSY_CRL_POLL);        
    } else if (result == AN_CERT_VALIDITY_UNKNOWN) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
            "\n%sNeighbor [%s] domain cert validation unknown "
            "due to API error", 
            an_bs_event, nbr->udi.data);
        an_ni_set_state(nbr, AN_NI_OUTSIDE);
        an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_UNKNOWN);
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%sNeighbor [%s] domain cert validation failed", 
                        an_bs_event, nbr->udi.data);
        an_ni_set_state(nbr, AN_NI_OUTSIDE);
        an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_FAILED);
    }
}
