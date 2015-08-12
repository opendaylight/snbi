/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "../al/an_addr.h"
#include "../al/an_logger.h"
#include "../al/an_cert.h"
#include "../al/an_sudi.h"
#include "../al/an_ipv6.h"
#include "../al/an_key.h"
#include "../al/an_cert.h"
#include "../al/an_if.h"
#include "../al/an_mem.h"
#include "../al/an_misc.h"
#include "../al/an_ntp.h"
#include "../al/an_str.h"
#include "../al/an_timer.h"
#include "an_msg_mgr.h"
#include "an_event_mgr.h"
#include "an_nbr_db.h"
#include "an_anra_db.h"
#include "an.h"
#include "an_bs.h"
#include "an_ni.h"
#include "an_anra.h"
//#include "an_topo_disc.h"

#define REJECTED_NBR_REFRESH_COUNT 2*10
#define AN_BS_MAX_WAIT_TIME_BEFORE_SELECTING_NEXT_ANR (5*60)
#define AN_ANRA_WITH_MAX_HASH TRUE
#define AN_ANRA_WITH_2ND_MAX_HASH FALSE

extern const uint8_t *an_cert_enum_get_string(an_cert_api_ret_enum enum_type);
void an_bs_trigger_request_message(an_msg_package *invite);
boolean bs_initialized = FALSE;
extern an_addr_t anr_reg_address[3];
an_timer an_revoke_check_timer = {0};
an_unix_time_t my_5perc_poll_timer = 0;
an_timer an_my_cert_renew_expire_timer = {0};
an_unix_time_t my_1perc_poll_timer = 0;
an_unix_time_t an_crl_expire_interval = 0;


static uint8_t *an_bs_state_names[] = {
    "Bootstrap None",
    "Bootstrap Started",
    "Bootstrap Rejected",
    "Bootstrap Done",
};

uint8_t *
an_bs_get_nbr_state_name (an_nbr_t *nbr)
{
    if (!nbr) {
        return (NULL);
    }

    return (an_bs_state_names[nbr->bs_state]);
}

boolean
an_bs_is_initialized (void)
{
    return (bs_initialized);
}

void
an_bs_init (void)
{
    an_clock_set();

    bs_initialized = TRUE;
}

void
an_bs_uninit (void)
{
    /* Clear AN used crypto trustpoints */
    an_cert_unconfig_crl_auto_download();
    an_reset_ca_cert();
    bs_initialized = FALSE;
}

void 
an_bs_retrieve_saved_enrollment (void)
{
    uint8_t *tp_label = AN_DOMAIN_TP_LABEL;
    an_cert_t domain_ca_cert = {}, domain_device_cert = {};
    uint8_t *subject_cn = NULL, *device_name = NULL, 
            *domain_name = NULL, *subject_ou = NULL,*subject_temp = NULL;
    an_mac_addr *mac_address = NULL;
    uint16_t len = 0, device_name_len = 0, domain_name_len = 0;
    an_addr_t device_addr = AN_ADDR_ZERO;
    an_cert_api_ret_enum result;
    uint8_t *token;
    uint8_t delimiter[1] ={(uint8_t) AN_HOSTNAME_SUFFIX_DELIMITER};
    boolean expired_device = FALSE;

    if (!an_bs_is_initialized()) {
        return;
    }

    result = an_cert_get_ca_cert_from_tp(tp_label, &domain_ca_cert);
    if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                     "\n%sReading CA cert from tp returned error %s", 
                     an_bs_event, 
                     an_cert_enum_get_string(result));
        return;
    }
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                 "\n%sObtained CA Cert of Cert Len = %d from "
                 "Trustpoint: %s", an_bs_event,
                 domain_ca_cert.len, tp_label);

    result = an_cert_get_device_cert_from_tp(tp_label, &domain_device_cert);
    if (result == AN_CERT_EXPIRED_DEVICE_CERT_IN_TP) {
        expired_device = TRUE;
    } else if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                     "\n%sReading device cert from tp returned error %s", 
                     an_bs_event, 
                     an_cert_enum_get_string(result));
        return;
    }
        
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                 "\n%sObtained Device Cert of Cert Len = %d from " 
                 "Trustpoint: %s", an_bs_event, domain_device_cert.len, 
                 tp_label);

    result = an_cert_get_subject_cn(domain_device_cert, &subject_cn, &len);
    if(result != AN_CERT_API_SUCCESS) {
       DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sReading cn  field from subject returned "
                    "error %s", an_bs_event, 
                    an_cert_enum_get_string(result));
       return;
    }
    
    len = 0;
    result = an_cert_get_subject_ou(domain_device_cert, &subject_ou, &len);
    if(result != AN_CERT_API_SUCCESS) {
       DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sReading ou field from subject returned "
                    "error %s", an_bs_event,
                    an_cert_enum_get_string(result));
       return;
    }

    device_name = subject_cn;
    domain_name = subject_ou;
    subject_temp = an_malloc_guard(an_strlen(subject_temp)+1, 
                                   "AN Temp Subject cn");
    an_strncpy_s(subject_temp, an_strlen(subject_cn)+1, subject_cn, 
                 an_strlen(subject_cn));
    token = an_str_strtok(subject_temp, delimiter);
    while( token != NULL ) {
        if (!mac_address) {
            mac_address = token;
        }
        token = an_str_strtok (NULL, delimiter);
    }

    domain_name_len = an_strlen(domain_name);
    an_set_domain_id(domain_name);

    device_name_len = an_strlen(device_name);
    an_set_device_id(device_name);

    device_addr = an_get_v6addr_from_names(domain_name, mac_address, 
                                           device_name);
    an_set_device_ip(device_addr);

    an_set_ca_cert(domain_ca_cert);
    an_set_domain_cert(domain_device_cert, AN_CERT_TYPE_BOOTSTRAPPED);
    
    an_set_anr_macaddress(mac_address);
    an_free_guard(subject_cn);
    an_free_guard(subject_ou);
    an_free_guard(subject_temp);
    if (expired_device == TRUE) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
             "\n%sSave and reload - read expired cert from tp", an_bs_event);
        an_event_domain_device_cert_expired();
    } else {
        an_event_device_bootstrapped();
    }
}

boolean
an_bs_nbr_set_state (an_nbr_t *nbr, an_nbr_bs_state_e bs_state)
{
    if (!nbr) {
        return (FALSE);
    }

    nbr->bs_state = bs_state;
    return (TRUE);
}

an_nbr_bs_state_e
an_bs_nbr_get_state (an_nbr_t *nbr)
{
    if (!nbr) {
        return (AN_NBR_BOOTSTRAP_NONE);
    }
    
    return (nbr->bs_state);
}

void
an_bs_set_nbr_joined_domain (an_nbr_t *nbr)
{
    if (!nbr) {
        return;
    }

    if (nbr && (an_bs_nbr_get_state(nbr) != AN_NBR_BOOTSTRAP_NONE)) {
        an_bs_nbr_set_state(nbr, AN_NBR_BOOTSTRAP_DONE);
    }
}

boolean 
an_bs_validate_invite_cert_attributes (uint8_t *domain_id,
                                       an_cert_t cert) 
{
    if (!cert.data && !cert.len) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNULL Input Params, cert", an_bs_event);
        return (FALSE);
    }
    
    if (!domain_id) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDomain id is null, hence can't validate "
                      "cert attributes for Invite message", an_bs_event);
        return (FALSE);
    }
    if (!an_cert_validate_subject_ou(cert, domain_id)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to validate the subject attr OU for "
                     "BS invite message", an_bs_event);
        return (FALSE);
    }

    return (TRUE);
}

boolean
an_bs_validate_response_cert_attributes (uint8_t *device_id, uint8_t *domain_id,
                                         an_cert_t cert, an_udi_t message_udi)
{
    if (!cert.data && !cert.len) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNULL Input Params, cert", an_bs_event);
        return (FALSE);
    }

    if (!domain_id && !device_id) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNULL Input Params, device_id, domain_id",
                     an_bs_event);
        return (FALSE);
    }

    if (!an_cert_validate_subject_cn(cert, device_id)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to validate the subject attr CN for "
                     "bs response message", an_bs_event);
        return (FALSE);
    }
    
    if (!an_cert_validate_subject_ou(cert, domain_id)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to validate the subject attr OU for "
                     "BS Response message", an_bs_event);
        return (FALSE);
    }

    if (!an_cert_validate_subject_sn(cert, message_udi.data,
                                           message_udi.len)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to validate the subject attr SN for "
                     "BS Response message", an_bs_event);
        return (FALSE);
    }
    
    return (TRUE);
}

an_msg_package *
an_bs_prepare_message (an_nbr_t *nbr, an_msg_type_e type)
{
    an_msg_package *message = NULL;

    if (!an_bs_is_initialized()) {
        return (NULL);
    }
    
    if (!nbr || !nbr->udi.len || !nbr->udi.data) {
        return (NULL);
    }
    
    message = an_msg_mgr_get_empty_message_package();    
    if (!message) {
        return (NULL);
    }   

    message->dest = nbr->selected_anr_addr;
    message->iptable = an_get_iptable(); 
    message->src = an_ipv6_get_best_source_addr(message->dest, 
                                                message->iptable);
    message->ifhndl = 0;

    an_msg_mgr_init_header(message, AN_PROTO_ACP, type);

    if (nbr->udi.len) {
        message->udi.data = (uint8_t *)an_malloc_guard(nbr->udi.len, 
                                    "AN MSG UDI");
        if (!message->udi.data) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        } 
        message->udi.len = nbr->udi.len;
        an_memcpy_guard_s(message->udi.data, message->udi.len, 
                          nbr->udi.data, nbr->udi.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);
    }

    if (nbr->sudi.len) {
        message->sudi.data = (uint8_t *)an_malloc_guard(nbr->sudi.len, 
                               "AN MSG sUDI");
        if (!message->sudi.data) {
            an_msg_mgr_free_message_package(message);            
            return (NULL);
        }
        message->sudi.len = nbr->sudi.len;
        an_memcpy_guard_s(message->sudi.data, message->sudi.len, 
                          nbr->sudi.data, nbr->sudi.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_SUDI);
    }

    an_nbr_get_addr_and_ifs(nbr, &message->if_ipaddr, NULL, NULL);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_IF_IPADDR);

    return (message);
}

void
an_bs_trigger_nbr_connect_message (an_nbr_t *nbr)
{
    an_msg_package *message = NULL;
    an_addr_t anra_ip = AN_ADDR_ZERO;
    an_unix_time_t nbr_connect_triggered_time = 0;

    if (!an_bs_is_initialized()) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL,
                     "\n%sAutonomic Bootstrap process not initialized, "
                     "cant send Nbr Connect Message",
                     an_bs_pak);
        return;
    }

    if (!an_addr_is_zero(nbr->selected_anr_addr) && 
           nbr->selected_anr_reference_time != 0) {
        nbr_connect_triggered_time =
             an_unix_time_get_elapsed_time(nbr->selected_anr_reference_time);
    }

    if (an_anra_is_configured()) {
        nbr->selected_anr_addr = an_anra_get_registrar_ip();
    } else if ((nbr_connect_triggered_time <=
                AN_BS_MAX_WAIT_TIME_BEFORE_SELECTING_NEXT_ANR) &&
             (!an_addr_struct_comp(&nbr->selected_anr_addr, &AN_ADDR_ZERO))) {
               anra_ip = an_anra_select_anra_ip_from_srvc_db(nbr->udi, 
                                                  AN_ANRA_WITH_MAX_HASH);
               nbr->selected_anr_addr = anra_ip;
               nbr->selected_anr_reference_time =
                      an_unix_time_get_current_timestamp();
               DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                      "\n%sSelected ANR IP address from db is "
                      "%s %ld", an_bs_pak, 
                      an_addr_get_string(&nbr->selected_anr_addr),
                      nbr->selected_anr_reference_time);
    } else if (nbr_connect_triggered_time >
               AN_BS_MAX_WAIT_TIME_BEFORE_SELECTING_NEXT_ANR &&
               nbr->select_anr_retry_count < AN_SRVC_FIND_MAX_RETRY) {
               if (an_srvc_get_num_of_service(AN_ANR_SERVICE) > 1) {
                  anra_ip = an_anra_select_anra_ip_from_srvc_db(nbr->udi, 
                                            AN_ANRA_WITH_2ND_MAX_HASH);
                  nbr->selected_anr_reference_time =
                        an_unix_time_get_current_timestamp();
                  DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                        "\n%sSelecting 2nd ANR IP address from db"
                        "%s %ld", an_bs_pak, 
                  an_addr_get_string(&nbr->selected_anr_addr),
                  nbr->selected_anr_reference_time);
                  nbr->selected_anr_addr = anra_ip;
               }
    }

    if (an_addr_is_zero(nbr->selected_anr_addr)) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL,
                     "\n%sSelected Autonomic Registrar IP is NULL, "
                     "cannot send Nbr Connect Message",
                     an_bs_pak);
        return;
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL,
                     "\n%sSelected Autonomic Registrar IP is %s ",
                     an_bs_pak, an_addr_get_string(&nbr->selected_anr_addr));
        nbr->select_anr_retry_count++;
    }
    
    message = an_bs_prepare_message(nbr, AN_MSG_NBR_CONNECT); 
    if (!message) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL, 
                     "\n%sFailed to prepare the Nbr Connect Message", 
                     an_bs_pak);         
        return;
    }

    an_msg_mgr_send_message(message);
}

void
an_bs_init_nbr_bootstrap (an_nbr_t *nbr)
{
    uint8_t *my_domain_id = NULL;
    an_cert_t domain_cert = {};
    int ind = 0;

    if (!an_bs_is_initialized()) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                     "\n%sBS not intialized, "
                     "hence cant bootstrap the Nbr [%s]", 
                     an_bs_pak, nbr->udi.data);
        return;
    }

    if (!nbr) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL,
                     "\n%sNbr param is NULL, hence no bootstrap possible!",
                     an_bs_pak);
        return;
    }

    my_domain_id = an_get_domain_id();
    if (!my_domain_id || !an_get_domain_cert(&domain_cert)) {
        /* I am not in a domain, cannot bootstrap my neighbor */
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                     "\n%sThis device is not part of the AN domain, "
                     "hence cant bootstrap the Nbr [%s]", 
                     an_bs_pak, nbr->udi.data);

        return;
    }
    
    if (!domain_cert.valid) {
        /*If domain certificate is not valid, dont function as proxy*/
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                     "\n%sThis domain certificate is not valid, "
                     "hence cant bootstrap the Nbr [%s]", 
                     an_bs_pak, nbr->udi.data);
        return;
    }

    if (an_ni_is_nbr_inside(nbr)) {
        /* Neighbor and I are in the same domain, no need to bootstrap */
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
                 "\n%sNbr[%s] and this device already part of AN domain, "
                 "failed repeated bootstrap", an_bs_pak, nbr->udi.data);
        return;
    } else if (an_bs_nbr_get_state(nbr) == AN_NBR_BOOTSTRAP_REJECTED) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                  "\n%sNbr[%s] bootstrap state is AN_NBR_BOOTSTRAP_REJECTED,"
                  " can't bootstrap the Nbr", an_bs_pak, nbr->udi.data);   
        if (nbr->rejected_nbr_refresh_count >= REJECTED_NBR_REFRESH_COUNT) {
            nbr->rejected_nbr_refresh_count = 0;
            an_anra_deselect_anra_ip(nbr);
            an_bs_nbr_set_state(nbr, AN_NBR_BOOTSTRAP_NONE);
        } else {
            nbr->rejected_nbr_refresh_count++;
        }
        return;
    }

    /*Check if neighbor part of another domain,
      If so dont trigger neighbor connect*/
    if (nbr->domain_id) {
        an_strcmp_s(my_domain_id, AN_STR_MAX_LEN, nbr->domain_id, &ind);
        if (ind != 0) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                     "\n%sNbr is part of another domain, "
                     "hence cant bootstrap the Nbr [%s]", 
                     an_bs_pak, nbr->udi.data);
            return;
        }
    }
    if (an_ni_is_nbr_revoked(nbr)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
              "\n%sNbr[%s] was validated as revoked %d, will not "
              "trigger bootstrap invite to the Nbr", an_bs_event,
              nbr->udi.data); 
        return;
    }
    if (an_ni_is_nbr_expired(nbr))  {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
              "\n%sNbr[%s] was validated as revoked/expired state %d, now "
              "trigger bootstrap invite to the Nbr", an_bs_event, 
              nbr->udi.data,
              nbr->validation.result, nbr->ni_state);   
    }
    
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL, 
                 "\n%sProxy device triggering Nbr Connect Message"
                 " to Registrar for Nbr [%s]", 
                 an_bs_event, nbr->udi.data);

    if (an_bs_nbr_get_state(nbr) == AN_NBR_BOOTSTRAP_NONE) {
        an_anra_deselect_anra_ip(nbr);
    }

    an_bs_trigger_nbr_connect_message(nbr);
    
}

/* Return nbr  if the message is forwarded to known nbr
          NULL if the message is not forwarded or
                if there is an error
*/
an_nbr_t *
an_bs_forward_message_to_nbr (an_msg_package *message)
{
    an_nbr_t *nbr = NULL;
    an_cert_t domain_cert = {};
    uint8_t *my_domain_id = NULL;

    if (!message) {
        return (NULL);
    }

    if (!message->udi.len || !message->udi.data) {
        return (NULL);
    }

    if (!an_bs_is_initialized()) {
        return (NULL);
    }

    my_domain_id = an_get_domain_id();
    if (!my_domain_id || !an_get_domain_cert(&domain_cert)) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
                     "\n%sI am not in domain hence cant forward the " 
                     "Message [%s], drop it!", an_bs_pak, 
                     message->udi.data, 
                     an_get_msg_name(message->header.msg_type)); 
        return (NULL);
    }

    if (!domain_cert.valid) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
                     "\n%sMy domain cert not valid drop the" 
                     "Message [%s]!", an_bs_pak, 
                     message->udi.data, 
                     an_get_msg_name(message->header.msg_type)); 
        return (NULL);
    }

    nbr = an_nbr_db_search(message->udi);

    if (!nbr) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
                     "\n%sNbr[%s] not found in NBR DB to forward the " 
                     "Message [%s], hence ignore it", an_bs_pak, 
                     message->udi.data, 
                     an_get_msg_name(message->header.msg_type)); 
        return (NULL);

    } else {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
                     "\n%sNbr[%s] found in the NBR DB, hence forwarding " 
                     "Message [%s] to Nbr", an_bs_pak, message->udi.data, 
                     an_get_msg_name(message->header.msg_type));

        an_nbr_get_addr_and_ifs(nbr, &message->dest, &message->ifhndl, NULL);

        message->iptable = nbr->iptable;
		an_addr_set_from_v6addr(&message->src, 
								an_ipv6_get_ll(message->ifhndl));

        if (an_addr_equal(&message->dest, &message->src)) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
               "\n%sSource and Destination cant be same- drop the packet",
               an_bs_pak);
            return (NULL);
        }

        an_msg_mgr_send_message(message);
        return (nbr);
    }
}

boolean
an_bs_forward_message_to_anra (an_msg_package *message)
{
    an_nbr_t *nbr = NULL;

    if (!an_bs_is_initialized()) {
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                 "\n%sForwarding %s Message to Registrar",
                 an_bs_pak, an_get_msg_name(message->header.msg_type));
    
    nbr = an_nbr_db_search(message->udi);
    if (!nbr) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                     "\n%sNbr[%s] not found in NBR DB to forward the "
                     "Message to ANR[%s], hence ignore it", an_bs_pak,
                     message->udi.data,
                     an_get_msg_name(message->header.msg_type));
        return (FALSE);

    }  
    message->src = AN_ADDR_ZERO;
    message->dest = nbr->selected_anr_addr;

    if (an_addr_is_zero(nbr->selected_anr_addr)) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sSelected ANR address is zero, "
                     "can't forward message to ANRA", an_bs_pak);
        return (FALSE);
    }

    message->iptable = an_get_iptable();
    message->ifhndl = 0;
    
    an_msg_mgr_send_message(message);

    return (TRUE);
}

void
an_bs_bootstrap_device (an_msg_package *message)
{
    an_addr_t device_addr = AN_ADDR_ZERO;
    an_cert_api_ret_enum result;

    if (!an_bs_is_initialized()) {
        return;
    }

    if (!message) {
        return;
    }
    result = an_cert_set_domain_ca_cert(AN_DOMAIN_TP_LABEL, message->ca_cert);
    if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL,
                   "\n%sFrom Bootstrap Invite - cant import CA cert, %s",
                     an_bs_pak, an_cert_enum_get_string(result));
        return;
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                   "\n%sFrom Bootstrap Invitee - CA cert import success",
                    an_bs_pak);
    }
   
    an_set_domain_id(message->domain_id);
    an_set_device_id(message->device_id);
    an_set_anr_macaddress(message->macaddress); 
    device_addr = an_get_v6addr_from_names(message->domain_id, 
                                    message->macaddress, 
                                    message->device_id);
    an_set_device_ip(device_addr);
    an_set_anra_ip(message->anra_ipaddr);
    an_set_anra_if(message->ifhndl);
    an_set_ca_cert(message->ca_cert);

    an_bs_trigger_request_message(message);
    return;
}

void
an_bs_erase_unfinished_bootstrap (void)
{
    an_cert_t empty_cert = {0};

    an_set_device_id(NULL);
    an_set_domain_id(NULL);
    an_set_anr_macaddress(NULL);
    an_set_domain_cert(empty_cert, AN_CERT_TYPE_EMPTY);
    an_set_ca_cert(empty_cert);
    an_set_anra_ip(AN_ADDR_ZERO);
    an_set_iptable(0);
    an_set_afi(0);
    an_set_device_ip(AN_ADDR_ZERO);
    an_set_anra_if(0);
}

void
an_bs_incoming_enroll_quarantine_message(an_msg_package *message)
{
    an_udi_t my_udi = {};
    an_nbr_t *nbr = NULL;
    
    if (!an_bs_is_initialized()) {
        an_msg_mgr_free_message_package(message);
        return;
    }
    
    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                 "\n%sIncoming Bootstrap Message to enroll "
                 "quarantine device %s", an_bs_pak, message->udi.data);
    
    if (!message->udi.data || !message->udi.len ||
        !an_get_udi(&my_udi)) {
        an_msg_mgr_free_message_package(message);
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL, 
                     "\n%sIncoming BS Enroll Quarantine message has NULL UDI", 
                     an_bs_pak);   
        return;
    }

    nbr = an_nbr_db_search(message->udi);
    
    if (nbr) {
        if (an_bs_nbr_get_state(nbr) == AN_NBR_BOOTSTRAP_REJECTED) {
            an_bs_nbr_set_state(nbr, AN_NBR_BOOTSTRAP_NONE);
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                         "\n%sIncoming BS Enroll Quarantine Message, "
                         "changing Nbr [%s] state to unknown from rejected",
                         an_bs_pak, message->udi.data);
        }
    }
    an_msg_mgr_free_message_package(message);
    return;
}

void
an_bs_incoming_reject_message (an_msg_package *message)
{
    an_udi_t my_udi = {};
    an_nbr_t *nbr = NULL;

    if (!an_bs_is_initialized()) {
        an_msg_mgr_free_message_package(message);
        return;
    }

    if (!message->udi.data || !message->udi.len ||
        !an_get_udi(&my_udi)) {
        an_msg_mgr_free_message_package(message);
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL,
                     "\n%sNull UDI in BS Reject Message", an_bs_pak);
        return;
    }

    nbr = an_nbr_db_search(message->udi);
    if (nbr) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sBootstrap Rejected by Registrar", an_bs_pak);

        an_anra_deselect_anra_ip(nbr);

        if (an_bs_nbr_get_state(nbr) != AN_NBR_BOOTSTRAP_REJECTED) {
            an_bs_nbr_set_state(nbr, AN_NBR_BOOTSTRAP_REJECTED);

            /*
             * Check if Link is UP or DOWN before sending this message.
             * Also can register for a generic event update and
             * applications interested can act on the same.
             */
             //topo_nbr_update(nbr, TOPO_EVENT_DOMAIN_OUTSIDE_UP);
        }
    }
    an_msg_mgr_free_message_package(message);
    return;
}

void
an_bs_incoming_invite_message (an_msg_package *message)
{
    an_udi_t my_udi = {};
    an_nbr_t *nbr = NULL;
    uint8_t *data_extract = NULL;
    uint32_t data_len = 0;
    uint8_t* masa_trustpoint = "MASACRT";
    an_cert_t domain_cert = {};
    int indicator = 0;
    boolean clock_valid = FALSE;

    if (!message) {
        return;
    } 

    if (!message->udi.data || !message->udi.len ||
        !an_get_udi(&my_udi)) {
        an_msg_mgr_free_message_package(message);
        return;
    }

    if (!an_bs_is_initialized()) {
        an_msg_mgr_free_message_package(message);
        return;
    }

    an_memcmp_s(message->udi.data, AN_UDI_MAX_LEN, my_udi.data, 
                message->udi.len, &indicator);
    if ((message->udi.len == my_udi.len) && !indicator) {
        /* Message to me, proceed with processing */

        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                     "\n%sIncoming Message [%s] is for me[%s]", an_bs_pak, 
                     an_get_msg_name(message->header.msg_type), 
                     an_get_device_id());
   
    } else if ((nbr = an_bs_forward_message_to_nbr(message))) {
        /* Message to my neighbor, forwarded it */
        if (nbr && !an_ni_is_nbr_inside(nbr)) {
            an_bs_nbr_set_state(nbr, AN_NBR_BOOTSTRAP_STARTED);
        } 
        return;
        
    } else {
        /* Message not to me & not to my neighbors, drop it */
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
                     "\n%sMessage [%s] is neither to my neighbors or to me, "
                     "drop it!", an_bs_pak,
                     an_get_msg_name(message->header.msg_type));
        an_msg_mgr_free_message_package(message);
        return;
    }

    if (an_anra_is_configured() && 
        !an_addr_equal(&message->dest, &message->src)) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                   "\n%sDevice has a locally configured Autonomic Registrar,"
                   " ignoring the invite message from the other devices",
                     an_bs_pak);
        an_msg_mgr_free_message_package(message);
        return;
    }

    // This check is need to verify the ANRA cert suject_ou and 
    // the message domain_id TLV are equal. 
    if (!an_anra_is_configured()) { 
         
        if (!an_bs_validate_invite_cert_attributes(message->domain_id, 
                                                   message->anra_cert)) {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sIncoming BS invite's anra cert has "
                     "ummatched subject attributes", an_bs_event); 
            an_msg_mgr_free_message_package(message);
            return;
        }
    }
    if (an_get_domain_cert(&domain_cert)) {
        clock_valid = an_ntp_is_system_clock_valid();
        if (!clock_valid || (domain_cert.valid && clock_valid)) {
            //Note- Only if cert is valid- ignore the BS invite
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
                     "\n%sDevice[%s] has a valid domain cert, ignoring the"
                     "%s message", an_bs_pak, my_udi.data,
                     an_get_msg_name(message->header.msg_type));
            an_msg_mgr_free_message_package(message);
            return;
        }
    } 

    if (AN_CHECK_BIT_FLAGS(message->interest, AN_MSG_INT_ANRA_SIGN) && 
        AN_CHECK_BIT_FLAGS(message->interest, AN_MSG_INT_ANRA_CERT))    {
        if (!an_msg_mgr_verify_anra_signature(message, message->anra_cert)) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
                 "\n%sSignature validation of BS Invite failed", an_bs_pak);
            an_msg_mgr_free_message_package(message);
            return;
        }
    }else {
#if 0 // ToDo:: ANR signature not yet complete
        if (!an_addr_equal(&message->dest, &message->src)) { 
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                         "\n%sIncoming Invite message has no Signature,"
                         "hence dropping the message", an_bs_pak);
            an_msg_mgr_free_message_package(message);
            return;
        }

        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
          "\n%sANRA bootstrapping itself- skipping ANRA "
          "signature verification", an_bs_pak);
#endif
    }

    if (message->masa_sign.len) {
        if (!(an_smime_reply_verify_and_extract(message->masa_sign.data, 
                                                masa_trustpoint,
                                                &data_extract, &data_len))) {
            an_log(AN_LOG_MASA | AN_LOG_BS, "\nMASA verification failed");
            an_msg_mgr_free_message_package(message);
            return;
        } else { 
            if (NULL == an_strstr_ns(data_extract, "PID:")) {
                an_log(AN_LOG_MASA | AN_LOG_BS, 
                            "\nFailed to parse MASA response");
                an_msg_mgr_free_message_package(message);
                return;
            } else {
                an_log(AN_LOG_MASA | AN_LOG_BS, 
                       "\nMASA message verified, continuing with bootstrap");
            }
        }
        AN_CLEAR_BIT_FLAGS(message->interest, AN_MSG_INT_MASA_SIGN);
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
                 "\n%sMASA signature not present continuing ", an_bs_pak);
    }

    an_bs_bootstrap_device(message);
    an_msg_mgr_free_message_package(message);
}

void
an_bs_incoming_response_message (an_msg_package *response)
{
    an_udi_t my_udi = {};
    an_cert_t domain_cert = {};
    an_cert_api_ret_enum result;
    int indicator = 0;
    boolean clock_valid = FALSE;

    if (!an_bs_is_initialized()) {
        an_msg_mgr_free_message_package(response);
        return;
    }

    if (!response || !response->udi.data || !response->udi.len ||
        !an_get_udi(&my_udi)) {
        an_msg_mgr_free_message_package(response);
        return;
    }

    an_memcmp_s(response->udi.data, AN_UDI_MAX_LEN, my_udi.data, 
                my_udi.len, &indicator);
    if ((response->udi.len == my_udi.len) && !indicator) {
        /* Message to me, proceed with processing */

    } else if (an_bs_forward_message_to_nbr(response)) {
        /* Message to my neighbor, forwarded it */
        return;
    } else {
        /* Message not to me & not to my neighbors, drop it */
         DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
             "\n%sMessage [%s] is neither to my neighbors or to me- drop it",
             an_bs_pak, an_get_msg_name(response->header.msg_type));
        an_msg_mgr_free_message_package(response);
        return;
    }

    if (an_anra_is_configured() && 
        !an_addr_equal(&response->dest, &response->src)) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                   "\n%sDevice has a locally configured Autonomic Registrar,"
                   " ignoring the invite message from the other devices",
                   an_bs_pak);
        an_msg_mgr_free_message_package(response);
        return;
    }
   
    if (!an_bs_validate_response_cert_attributes(an_get_device_id(), 
                                                 an_get_domain_id(),
                                                 response->domain_cert,
                                                 response->udi)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sIncoming BS response's domain cert has "
                     "ummatched subject attributes", an_bs_event); 
        an_msg_mgr_free_message_package(response);
        return;
    }

    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL, 
            "\n%sReceived Domain Cert from Autonomic Registrar", an_bs_pak);   
    if (an_get_domain_cert(&domain_cert)) {
        clock_valid = an_ntp_is_system_clock_valid();
        if (!clock_valid || (clock_valid && domain_cert.valid)) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_INFO, NULL,
                 "\n%sDevice [%s] already bootstrapped, ignoring repeated "
                 "Bootstrap Response Message!", an_bs_pak, my_udi.data);
            an_msg_mgr_free_message_package(response);
	        return;
        }
    }

    an_set_domain_cert(response->domain_cert, AN_CERT_TYPE_BOOTSTRAPPED); 
        
    result = an_cert_set_domain_device_cert(AN_DOMAIN_TP_LABEL, response->domain_cert);
    if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL,
                   "\n%sIn Incoming Bootstrap Response's domain cert import"
                     " failed with error %s", an_bs_pak, 
                     an_cert_enum_get_string(result));
        an_msg_mgr_free_message_package(response);
        return;
    }
    an_msg_mgr_free_message_package(response);

    an_config_save();
    an_event_device_bootstrapped();
    if (an_anra_is_configured()) {
        an_event_anra_up_locally();
    }
}

void
an_bs_trigger_request_message (an_msg_package *invite)
{
    uint8_t *key_label = AN_DOMAIN_KEY_LABEL; 
	uint8_t *tp_label = AN_DOMAIN_TP_LABEL;
    an_key_t public_key = {};
    an_cert_req_t pkcs10 = {};
    an_sign_t pkcs10_sign = {};
    an_msg_package *bs_request = NULL;
    uint8_t *device_name = NULL;
    uint8_t *domain_name = NULL;
    an_mac_addr *mac_address = NULL;
    an_cert_t domain_cert = {};
    an_cert_api_ret_enum result;
    boolean clock_valid = FALSE;

    if (!an_bs_is_initialized()) {
        return;
    }

    if (an_get_domain_cert(&domain_cert)) {
        clock_valid = an_ntp_is_system_clock_valid();
        if (!clock_valid || (clock_valid && domain_cert.valid)) {
            /*If u have valid domain cert- dont trigger BS REQ messg*/
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL, 
                  "\n%sHave valid domain cert- dont trigger CSR request",
                  an_bs_pak);
            return;
        }
    }

    device_name = an_get_device_id();
    domain_name = an_get_domain_id();
    mac_address = an_get_anr_macaddress();

    if (!device_name || !domain_name) {
        return;
    }

    bs_request = an_msg_mgr_get_empty_message_package();    
    if (!bs_request) {
        return;
    }

    public_key = an_get_public_key(key_label);
    if (!public_key.len || !public_key.data) {
        an_msg_mgr_free_message_package(bs_request);
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL,
                     "\n%sWhile triggerring Bootstrap Request Message, "
                     "failed to generate AN domain keypair", an_bs_pak);
        return;
    }
    
    result = an_cert_generate_request(tp_label, key_label, mac_address, 
						device_name, domain_name, &pkcs10, &pkcs10_sign);
    if (result != AN_CERT_API_SUCCESS) {
        an_msg_mgr_free_message_package(bs_request);
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL, 
                  "\n%sWhile triggerring Bootstrap Request Message, "
                  "CSR generation failed with error %s",
                   an_bs_pak, an_cert_enum_get_string(result));
        return;
    }
    an_msg_mgr_init_header(bs_request, AN_PROTO_ACP, 
                           AN_MSG_BS_REQUEST);

    bs_request->udi.len = invite->udi.len;
    bs_request->udi.data = (uint8_t *)an_malloc_guard(invite->udi.len, 
                                                    "AN BS Req MSG UDI");
    if (!bs_request->udi.data) {
        an_msg_mgr_free_message_package(bs_request);
        return;
    }
    an_memcpy_guard_s(bs_request->udi.data, bs_request->udi.len, 
                        invite->udi.data, invite->udi.len);
    AN_SET_BIT_FLAGS(bs_request->interest, AN_MSG_INT_UDI);

	if (pkcs10_sign.len) {
		bs_request->cert_request = pkcs10; 
		AN_SET_BIT_FLAGS(bs_request->interest, AN_MSG_INT_UNSIGNED_CERT_REQ);
		bs_request->cert_req_sign = pkcs10_sign;
		AN_SET_BIT_FLAGS(bs_request->interest, AN_MSG_INT_CERT_REQ_SIGN);

	} else {
		bs_request->signed_cert_request = pkcs10;
		AN_SET_BIT_FLAGS(bs_request->interest, AN_MSG_INT_SIGNED_CERT_REQ);
	}
    bs_request->public_key.len = public_key.len;
    bs_request->public_key.data = (uint8_t *)an_malloc_guard(public_key.len, 
                                             "AN BS Req MSG Public Key");
    if (!bs_request->public_key.data) {
        an_msg_mgr_free_message_package(bs_request);
        return;
    } 
    an_memcpy_guard_s(bs_request->public_key.data, bs_request->public_key.len, 
                                        public_key.data, public_key.len);
    AN_SET_BIT_FLAGS(bs_request->interest, AN_MSG_INT_PUB_KEY);

    bs_request->src = invite->dest;
    bs_request->dest = invite->src;
    bs_request->iptable = an_get_iptable();
    bs_request->ifhndl = invite->ifhndl;
    an_msg_mgr_send_message(bs_request);

}

void
an_bs_ni_cert_timer_expired_event_handler (void *nbr_info_ptr)
{
    an_nbr_t *nbr = NULL;

    if (!nbr_info_ptr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr info is NULL, Cant handle ni cert timer expiry.", an_bs_event);
        return;
    }
    nbr = (an_nbr_t *)nbr_info_ptr;

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sCert Req timer reset for nbr [%s]",
                 an_bs_event, nbr->udi.data);

    an_ni_cert_request_retry(nbr);
}

void
an_bs_nbr_add_event_handler (void *nbr_info_ptr)
{
    an_nbr_t *nbr = NULL;

    if (!nbr_info_ptr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr info is NULL, Cant handle nbr add.", an_bs_event);
        return;
    }
    nbr = (an_nbr_t *)nbr_info_ptr;

    if (!nbr || !nbr->udi.data) {
        return;
    }   
    an_ni_cert_request(nbr);
}

void
an_bs_restart_revoke_check_timer (an_unix_time_t revoke_interval)
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
an_bs_cert_revoke_check_timer_expired_event_handler (void *info_ptr)
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
                   an_bs_restart_revoke_check_timer(revoke_interval);
                   return;
               }
           } else {
               //CRL not present- PKI Validate will trigger CRL download
               //Now rerun revoke check timer after 3 mins
               DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                   "\n%sNo CRL available now, rerun Cert Validation check "
                   "cert validation", an_bs_event);
               an_bs_restart_revoke_check_timer(
                    AN_CERT_WAIT_TO_RERUN_REVOKE_CHECK);
           }
       }
   }else {
       DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
          "\n%sAN Domain cert is being renewed- will do without CRL "
          "cert validation", an_bs_event);
       an_ni_validate_nbrs();
       an_bs_restart_revoke_check_timer(
                    AN_CERT_WAIT_TO_RERUN_REVOKE_CHECK);
   }
}

void
an_bs_nbr_cert_revalidate_timer_expired_event_handler (void *nbr_info_ptr)
{
    an_nbr_t *nbr = NULL;

   if (!nbr_info_ptr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr info is NULL, Cant handle ni cert timer expiry.", an_bs_event);
        return;
   }
   nbr = (an_nbr_t *)nbr_info_ptr;

   DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
             "\n%sCRL check returned PKI_API_VERIFY_FAILURE, "
             "cert not validated, hence revalidate Nbr certificate",
             an_bs_event);
   an_ni_validate_with_crl(nbr);
}

void
an_bs_nbr_cert_renew_timer_expired_event_handler (void *nbr_info_ptr)
{
    uint8_t now_time_str[TIME_DIFF_STR];
    an_unix_msec_time_t now;
    an_nbr_t *nbr = NULL;

    if (!nbr_info_ptr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr info is NULL, Cant handle ni cert timer expiry.", an_bs_event);
        return;
    }
    nbr = (an_nbr_t *)nbr_info_ptr;

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
an_bs_my_cert_renew_timer_expired_event_handler (void *info_ptr)
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
an_bs_domain_device_cert_expired_event_handler (void *info_ptr)
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
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
             "\n%sClean up expired device for new bootstrap", an_bs_event);

    /*Stop all BS related timers on the expired device*/

    //Do not stop my cert expire timer- when u receive new certificate stop it
    an_timer_stop(&an_revoke_check_timer);
    an_crl_expire_interval = 0;
}

void
an_bs_start_my_cert_expire_timer (void)
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
an_bs_start_revoke_check_timer (void)
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
an_bs_domain_device_cert_renewed_event_handler (void *info_ptr)
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
    an_bs_start_my_cert_expire_timer();
    an_bs_start_revoke_check_timer();
    return;
}

void
an_bs_validation_cert_response_obtained_event_handler (void *info_ptr)
{
    an_event_validation_cert_response_info_t *cert_resp_info = NULL;
    
    if (!info_ptr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sCERT Response is NULL", an_bs_event);
        return;
    }
    cert_resp_info = (an_event_validation_cert_response_info_t *)info_ptr;

    an_ni_validation_cert_response_obtained(cert_resp_info->status, cert_resp_info->device_ctx);
}

void
an_bs_nbr_inside_domain_event_handler (void *nbr_info_ptr)
{
    an_cert_t domain_cert = {};
    an_if_t nbr_ifhndl = 0;
    an_nbr_t *nbr = NULL;

    if(!nbr_info_ptr) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle nbr add event ");
        return;
    }
    nbr = (an_nbr_t *)nbr_info_ptr;
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
    }
}

void
an_bs_nbr_outside_domain_event_handler (void *nbr_info_ptr)
{
    an_nbr_t *nbr = NULL;

    if(!nbr_info_ptr) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle nbr add event ");
        return;
    }
    nbr = (an_nbr_t *)nbr_info_ptr;
    an_bs_init_nbr_bootstrap(nbr);
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
an_bs_anr_up_locally_event_handler (void *info_ptr)
{
    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
             "\n%sAutonomic Registrar is Locally UP, walking the Nbr DB to "
             "initialize the Nbr bootstrap", an_ra_event);
    an_nbr_db_walk(an_bs_init_nbr_bootstrap_cb, NULL);
    an_cert_config_crl_auto_download(AN_CERT_ANRA_CRL_PREPUBLISH_INTERVAL);
}

void
an_bs_anr_reachable_event_handler (void *info_ptr)
{
    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_INFO, NULL,
             "\n%sAutonomic Registrar is reachable now, walk the Nbr DB to "
             "initiate Nbr bootstrap", an_ra_event);

    //topo_disc_adv();
    an_nbr_db_walk(an_bs_init_nbr_bootstrap_cb, NULL);
}

void
an_bs_clock_synchronised_event_handler (void *info_ptr)
{
    an_ni_validate_expired_nbrs();
}

void
an_bs_acp_initialised_event_handler (void *info_ptr)
{
   an_cert_api_ret_enum result;
   an_addr_t anra_ip = AN_ADDR_ZERO;

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
}

void
an_bs_nbr_refreshed_event_handler (void *link_info_ptr)
{
    an_nbr_t *nbr = NULL;
    an_nbr_link_context_t *nbr_link_ctx = NULL;

    if (!link_info_ptr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr link info is NULL, Cant handle acp link removal event", an_bs_event);
        return;
    }

    nbr_link_ctx = (an_nbr_link_context_t *)link_info_ptr;
    if (nbr_link_ctx == NULL)
    {
       DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sContext is NULL in nbr refreshed event", an_nd_event);
       return;
    }

    nbr = nbr_link_ctx->nbr;
     
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
}

void
an_bs_nbr_params_changed_event_handler (void *nbr_info_ptr)
{
    an_nbr_t *nbr = NULL;

    if (!nbr_info_ptr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr info is NULL, Cant handle ni cert"
               " timer expiry.", an_bs_event);
        return;
    }
    nbr = (an_nbr_t *)nbr_info_ptr;

    if (!nbr) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sContext is NULL in nbr params" 
                    " changed event", an_nd_event);
        return;
    }
    an_ni_cert_request(nbr);
}

void
an_bs_set_revoke_timer_interval (uint16_t interval_in_mins)
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
an_bs_device_bootstrap_event_handler (void *info_ptr)
{
    an_ni_validate_nbrs();

    if (an_timer_is_running(&an_my_cert_renew_expire_timer)) {
        an_timer_stop(&an_my_cert_renew_expire_timer);
    }
    an_bs_start_my_cert_expire_timer();
    an_bs_start_revoke_check_timer();
    an_cert_config_crl_auto_download(AN_CERT_CRL_PREPUBLISH_INTERVAL);
}

void
an_bs_sudi_available_event_handler (void *info_ptr)
{
    an_bs_retrieve_saved_enrollment();
}

void
an_bs_udi_available_event_handler (void *info_ptr)
{
    an_udi_t my_udi = {};

    if (!an_get_udi(&my_udi)) {
        return;
    }
    if (an_create_trustpoint("MASACRT", "nvram:masa_crt.pem")) {
        an_log(AN_LOG_MASA | AN_LOG_EVENT,
               "\nAN: Event - Created MASA trustpoint");
    } else {
        an_log(AN_LOG_MASA | AN_LOG_EVENT,
               "\nAN: Event - Failed to create MASA trustpoint");
    }

    if (an_is_active_rp()) {
        an_bs_retrieve_saved_enrollment();
    }
}

/*-------------------AN BS register for event handlers --------------------*/
void
an_bs_register_for_events (void) 
{
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_TIMER_NI_CERT_REQUEST_EXPIRED, 
                        an_bs_ni_cert_timer_expired_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_NBR_ADD, an_bs_nbr_add_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_TIMER_CERT_REVOKE_CHECK_EXPIRED, 
                        an_bs_cert_revoke_check_timer_expired_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_TIMER_NBR_CERT_REVALIDATE_EXPIRED, 
                        an_bs_nbr_cert_revalidate_timer_expired_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_TIMER_NBR_CERT_RENEW_EXPIRED, 
                        an_bs_nbr_cert_renew_timer_expired_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_TIMER_MY_CERT_RENEW_EXPIRED, 
                        an_bs_my_cert_renew_timer_expired_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_DOMAIN_DEVICE_CERT_EXPIRED, 
                        an_bs_domain_device_cert_expired_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_DOMAIN_DEVICE_CERT_RENEWED, 
                        an_bs_domain_device_cert_renewed_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_VALIDATION_CERT_RESPONSE, 
                        an_bs_validation_cert_response_obtained_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_NBR_INSIDE_DOMAIN, 
                        an_bs_nbr_inside_domain_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_NBR_OUTSIDE_DOMAIN, 
                        an_bs_nbr_outside_domain_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_ANR_UP_LOCALLY, 
                        an_bs_anr_up_locally_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_ANR_REACHABLE, 
                        an_bs_anr_reachable_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_CLOCK_SYNCHRONISED, 
                        an_bs_clock_synchronised_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_ACP_INIT, an_bs_acp_initialised_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_NBR_REFRESHED, 
                        an_bs_nbr_refreshed_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_NBR_PARAMS_CAHNGED, 
                        an_bs_nbr_params_changed_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_DEVICE_BOOTSTRAP, 
                        an_bs_device_bootstrap_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_SUDI_AVAILABLE, 
                        an_bs_sudi_available_event_handler);
    an_event_register_consumer(AN_MODULE_BS,
                        AN_EVENT_UDI_AVAILABLE, 
                        an_bs_udi_available_event_handler);
}

