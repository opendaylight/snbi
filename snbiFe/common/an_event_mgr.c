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
#include "an_cd.h"
#include "an_nd.h"
#include "an_ni.h"
#include "an_bs.h"
#include "an_nbr_db.h"
#include "an_anra.h"
#include "an_anra_db.h"
#include "an_if_mgr.h"
#include "an_acp.h"
#include "an_idp.h"
#include "an_srvc.h"
#include "an.h"
#include "an_event_mgr.h"
//#include "an_topo_disc.h"
#include "an_srvc_db.h"
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
#include "an_intent.h"
#include "an_config_download.h"
#include "an_external_anra.h"

extern void an_detach_from_environment(void);
extern void an_attach_to_environment(void);
extern void an_parser_init(void);
extern an_avl_tree an_mem_elem_tree;
extern an_avl_walk_e an_mem_elem_db_uninit_cb(an_avl_node_t *node, void *args);

extern an_timer an_generictimer;
extern an_timer an_revoke_check_timer;
extern an_timer an_my_cert_renew_expire_timer;
extern an_unix_time_t my_5perc_poll_timer;
extern an_unix_time_t my_1perc_poll_timer;
extern an_timer an_anra_bs_thyself_retry_timer;

extern an_unix_time_t an_crl_expire_interval;

extern an_mem_chunkpool_t *an_address_saved_context_pool;
extern an_mem_chunkpool_t *an_aaa_saved_context_pool;
extern uint32_t an_cd_untagged_refresh_expire_cnt;
extern boolean an_intent_parse_file_after_system_configured;
extern boolean an_intent_stale_cleanup_required;
extern uint32_t an_intent_stale_cleanup_wait_cnt;
extern an_addr_t g_ntp_ra_address;

void
an_event_interface_up (an_if_t ifhndl)
{

    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sInterface %s is UP", an_nd_event, an_if_get_name(ifhndl));
    an_event_notify_consumers(AN_EVENT_INTERFACE_UP, &ifhndl);
}

void
an_event_interface_down (an_if_t ifhndl)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sInterface %s is DOWN", an_nd_event, 
                 an_if_get_name(ifhndl));
    an_event_notify_consumers(AN_EVENT_INTERFACE_DOWN, &ifhndl);
}

void
an_event_interface_erased (an_if_t ifhndl)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sInterface %s is Erased", an_nd_event, 
                 an_if_get_name(ifhndl));
    an_event_notify_consumers(AN_EVENT_INTERFACE_ERASED, &ifhndl);
}

void
an_event_registrar_up (void)
{
    an_event_notify_consumers(AN_EVENT_ANR_LIVE_PENDING, NULL);
}

void
an_event_registrar_shut (void)
{
    an_event_notify_consumers(AN_EVENT_ANR_SHUT_PENDING, NULL);
}

void
an_event_no_registrar (void)
{
    an_event_notify_consumers(AN_EVENT_ANR_DELETE_PENDING, NULL);
}

void
an_event_service_received (void *context, int value)
{
    an_event_service_discovery_info_t srv_context = {};
    
    srv_context.context = context;
    srv_context.value = value;
    an_event_notify_consumers(AN_EVENT_SD_SRVC_RECEIVED, &srv_context);

}

void 
an_event_service_resolved (void *context, int value)
{
    an_event_service_discovery_info_t srv_context = {};

    srv_context.context = context;
    srv_context.value = value;
    an_event_notify_consumers(AN_EVENT_SD_SRVC_RESOLVED, &srv_context);
}

void
an_event_host_resolved (void *context, int value)
{
    an_event_service_discovery_info_t srv_context = {};
    
    srv_context.context = context;
    srv_context.value = value;
    an_event_notify_consumers(AN_EVENT_SD_HOST_RESOLVED, &srv_context);
}

void
an_event_autonomics_uninit (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                   "\n%sAutonomic uninit", an_nd_event);
    //Disable AN modules
    an_sudi_uninit();
    //topo_disc_uninit(); 
    an_idp_uninit(); 

    //Stop services before bring down ACP    
    an_srvc_db_uninit();
    an_sd_cfg_global_commands(FALSE);

    /* Reset ACP */
    an_acp_uninit();
    an_aaa_set_new_model(FALSE);
    
    /* Remove the certificates and trustpoints */    
    an_bs_uninit();
 
    /* Reset ND */
    an_nd_uninit();
    an_cd_uninit();
    an_cnp_uninit();
    an_if_uninit();

    an_clear_service_info_db();

    /* Final Global Reset */
    an_reset_global_info();
    an_set_device_enrollment_url(FALSE);

    /* AN DBs Clear */
    an_nbr_db_init();
    an_acp_client_db_init();          
    
    an_platform_specific_uninit();
    an_avl_uninit(&an_mem_elem_tree, an_mem_elem_db_uninit_cb);

    /*Stop all timers on device*/
    an_timer_stop(&an_anra_bs_thyself_retry_timer);
    an_timer_stop(&an_config_download_timer);
    an_timer_stop(&an_my_cert_renew_expire_timer);
    an_timer_stop(&an_generictimer);
    an_timer_stop(&an_revoke_check_timer);

    an_detach_from_environment();

    an_crl_expire_interval = 0;
}    

void
an_event_autonomics_init (void)
{
    an_if_mgr_register_for_events();
    an_generic_register_for_events();
    an_cd_register_for_events();
    an_nd_register_for_events();
    an_bs_register_for_events();
    an_acp_register_for_events();
    an_idp_register_for_events();
    an_intent_register_for_events();
    an_anr_register_for_events();
    an_srvc_register_for_events();
    an_conig_download_register_for_events();
    an_external_anra_register_for_events();
    /* Infra enable for AN */
    an_log_init();  
    an_register_for_sig_quit();    
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAutonomic init", an_nd_event);

    an_timer_services_init();
    an_parser_init();
    an_attach_to_environment();

    an_acp_client_db_init();
    an_nbr_db_init();
    an_cnp_init();
    
    /* Final Global Reset */
    an_reset_global_info();

    /* AN Modules enable */
    an_str_buffer_init();
    an_addr_generator_init();
    an_bs_init();
    an_idp_init();
    //topo_disc_init();
    an_timer_init(&an_revoke_check_timer, AN_TIMER_TYPE_CHECK_CERT_REVOKE, NULL, FALSE);
    an_timer_init(&an_generictimer, AN_TIMER_TYPE_GENERIC, NULL, FALSE);
    an_timer_init(&an_my_cert_renew_expire_timer, AN_TIMER_TYPE_MY_CERT_EXPIRE,
                   NULL, FALSE);
    an_timer_init(&an_config_download_timer, AN_TIMER_TYPE_CONFIG_DOWNLOAD, 
                  NULL, FALSE);
    an_timer_init(&an_anra_bs_thyself_retry_timer, 
                  AN_TIMER_TYPE_ANRA_BS_THYSELF_RETRY, NULL, FALSE);
    if (an_system_is_configured()) {
        an_platform_specific_init();
        an_sudi_init();
    }
    an_intent_init();
    an_cd_start_punt(an_multicast,AN_CD_IEEE_ETHERTYPE,0);
    an_external_ra_init();
}

void
an_event_registrar_uninit (void)
{
    an_event_notify_consumers(AN_EVENT_ANR_UNINIT, NULL);
}

void
an_event_system_configured (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sSystem configuring", an_nd_event);
    an_event_notify_consumers(AN_EVENT_SYSTEM_CONFIGURED, NULL);
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

    an_syslog(AN_SYSLOG_UDI_AVAILABLE, my_udi.data);
    an_event_notify_consumers(AN_EVENT_UDI_AVAILABLE, NULL);
}

void
an_event_sudi_available (void)
{
    an_udi_t my_udi = {};
    
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sSUDI is available now", an_nd_event);
    an_sudi_get_udi(&my_udi);

    an_syslog(AN_SYSLOG_SUDI_AVAILABLE, my_udi.data);

    an_event_notify_consumers(AN_EVENT_SUDI_AVAILABLE, NULL);
}

void
an_event_ni_cert_request_timer_expired (void *nbr)
{
    an_event_notify_consumers(AN_EVENT_TIMER_NI_CERT_REQUEST_EXPIRED, nbr);
}

void
an_event_hello_refresh_timer_expired (void)
{
    an_event_notify_consumers(AN_EVENT_TIMER_HELLO_REFRESH_EXPIRED, NULL);
}

void
an_event_interface_activated (an_if_info_t *an_if_info)
{
    an_event_notify_consumers(AN_EVENT_INTERFACE_ACTIVATE, &an_if_info->ifhndl);
}

void
an_event_interface_deactivated (an_if_t ifhndl)
{
    an_event_notify_consumers(AN_EVENT_INTERFACE_DEACTIVATE, &ifhndl);
}

void
an_event_nbr_link_add (void *nbr, void *nbr_link_data)
{
    an_event_nbr_link_add_lost_info_t nbr_link_info = {};

    nbr_link_info.nbr = nbr;
    nbr_link_info.nbr_link_data = nbr_link_data;
    an_event_notify_consumers(AN_EVENT_NBR_LINK_ADD, &nbr_link_info); 
}

void
an_event_nbr_link_cleanup_timer_expired (an_nbr_link_context_t *nbr_link_ctx)
{
     DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_INFO, NULL,
                  "\n%sNbr per link cleanup timer Expired", an_nd_event);

     an_event_notify_consumers(AN_EVENT_TIMER_NBR_LINK_CLEANUP_EXPIRED, nbr_link_ctx);
}

void
an_event_nbr_inside_domain (void *nbr) 
{
    an_event_notify_consumers(AN_EVENT_NBR_INSIDE_DOMAIN, nbr);
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
        an_acp_remove_to_nbr_for_all_valid_nbr_links(nbr);
    }
    an_bs_init_nbr_bootstrap(nbr);
    /* Once the Async changes are done, Consumers can be notified 
        Now the functions are directly called in event manager */
    //an_event_notify_consumers(AN_EVENT_NBR_OUTSIDE_DOMAIN, nbr);
}

void
an_event_nbr_add (void *nbr)
{
    an_event_notify_consumers(AN_EVENT_NBR_ADD, nbr);    
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

    an_event_notify_consumers(AN_EVENT_DEVICE_BOOTSTRAP, NULL);

}

void 
an_event_device_cert_enroll_success (uchar *cert_der,
                uint16_t cert_len, an_udi_t dest_udi,
                an_addr_t proxy_device, an_iptable_t iptable)
{
    an_event_cert_enroll_info_t cert_enroll_info = {};
    cert_enroll_info.cert_der = cert_der;
    cert_enroll_info.cert_len = cert_len;
    cert_enroll_info.dest_udi = dest_udi;
    cert_enroll_info.proxy_device = proxy_device;
    cert_enroll_info.iptable = iptable;

    an_event_notify_consumers(AN_EVENT_DEVICE_CERT_ENROLL_SUCCESS, &cert_enroll_info);
}

void
an_event_device_cert_enroll_failed (void)
{
    an_event_notify_consumers(AN_EVENT_DEVICE_CERT_ENROLL_FAILED, NULL);
}

void
an_event_anra_bootstrap_retry_timer_expired (void)
{   
    an_event_notify_consumers(AN_EVENT_TIMER_ANR_BS_RETRY_EXPIRED, NULL); 
}

void
an_event_external_anra_bootstrap_retry_timer_expired (void)
{
    an_event_notify_consumers(AN_EVENT_TIMER_EXTERNAL_ANR_BS_RETRY_EXPIRED,
                              NULL);
}

void
an_event_anra_up_locally (void)
{
    an_event_notify_consumers(AN_EVENT_ANR_UP_LOCALLY, NULL);
}

void
an_event_anra_shut (void)
{
    an_event_notify_consumers(AN_EVENT_ANR_SHUT, NULL);
}

void
an_event_anra_reachable (void)
{
    an_event_notify_consumers(AN_EVENT_ANR_REACHABLE, NULL);
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
    an_event_notify_consumers(AN_EVENT_DOMAIN_DEVICE_CERT_RENEWED, NULL);
}

void
an_event_domain_device_cert_expired (void)
{
    an_event_notify_consumers(AN_EVENT_DOMAIN_DEVICE_CERT_EXPIRED, NULL);
}

void
an_event_domain_device_cert_learnt (void)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sDomain Device Certficate learnt", an_bs_event); 
}

void
an_event_nbr_params_changed (an_nbr_t *nbr)
{
     an_event_notify_consumers(AN_EVENT_NBR_PARAMS_CAHNGED, nbr);
}

void
an_event_nbr_refreshed (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    an_nbr_link_context_t nbr_link_info = {};
    nbr_link_info.nbr = nbr;
    nbr_link_info.nbr_link_data = nbr_link_data;
    an_event_notify_consumers(AN_EVENT_NBR_REFRESHED, &nbr_link_info);
}

void
an_event_acp_on_nbr_link_created (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    an_nbr_link_context_t nbr_link_info = {};
    nbr_link_info.nbr = nbr;
    nbr_link_info.nbr_link_data = nbr_link_data;
    an_event_notify_consumers(AN_EVENT_ACP_ON_LINK_CREATED, &nbr_link_info);
}

void
an_event_acp_on_nbr_link_removed (an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data)
{
    an_nbr_link_context_t nbr_link_info = {};
    nbr_link_info.nbr = nbr;
    nbr_link_info.nbr_link_data = nbr_link_data;
    an_event_notify_consumers(AN_EVENT_ACP_ON_LINK_REMOVED, &nbr_link_info);
}


void
an_event_if_autonomic_enable (an_if_t ifhndl)
{
    an_event_notify_consumers(AN_EVENT_INTF_AUTONOMIC_ENABLE, &ifhndl);
}


void
an_event_if_autonomic_disable (an_if_t ifhndl)
{
    an_event_notify_consumers(AN_EVENT_INTF_AUTONOMIC_DISABLE, &ifhndl);
}

void
an_event_acp_initialized (void)
{
    an_event_notify_consumers(AN_EVENT_ACP_INIT, NULL);
}

void
an_event_acp_pre_uninitialization (void)
{
    an_event_notify_consumers(AN_EVENT_ACP_PRE_UNINIT, NULL);
}

void
an_event_acp_uninitialized (void)
{
    an_event_notify_consumers(AN_EVENT_ACP_UNINIT, NULL);
}


void
an_event_clock_synchronized (void)
{
    an_event_notify_consumers(AN_EVENT_CLOCK_SYNCHRONISED, NULL);
}

void
an_event_generic_timer_expired (void)
{
   an_event_notify_consumers(AN_EVENT_TIMER_GENERIC_EXPIRED, NULL); 
}

void
an_event_nbr_cert_in_validity_expired_state (an_nbr_t *nbr)
{
    an_event_notify_consumers(AN_EVENT_NBR_CERT_VALIDITY_EXPIRED, nbr);
}

void
an_event_cert_revoke_check_timer_expired (void)
{
    an_event_notify_consumers(AN_EVENT_TIMER_CERT_REVOKE_CHECK_EXPIRED, NULL);
}

void
an_event_nbr_cert_revalidate_timer_expired (void *nbr)
{
    an_event_notify_consumers(AN_EVENT_TIMER_NBR_CERT_REVALIDATE_EXPIRED, nbr);
}

void 
an_event_nbr_cert_renew_timer_expired (void *nbr)
{
    an_event_notify_consumers(AN_EVENT_TIMER_NBR_CERT_RENEW_EXPIRED, nbr);
}

void 
an_event_my_cert_renew_timer_expired (void)
{
    an_event_notify_consumers(AN_EVENT_TIMER_MY_CERT_RENEW_EXPIRED, NULL);
}

void
an_event_validation_cert_response_obtained (an_cert_validation_result_e status, 
                                            void *device_ctx)
{
    an_event_validation_cert_response_info_t cert_response_info = {};
    cert_response_info.status = status;
    cert_response_info.device_ctx = device_ctx;
    
    an_event_notify_consumers(AN_EVENT_VALIDATION_CERT_RESPONSE, &cert_response_info);
}

