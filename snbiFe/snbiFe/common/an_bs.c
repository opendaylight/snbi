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

extern const uint8_t *an_cert_enum_get_string(an_cert_api_ret_enum enum_type);
void an_bs_trigger_request_message(an_msg_package *invite);
boolean bs_initialized = FALSE;
extern an_addr_t anr_reg_address[3];

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
    an_reset_ca_cert();
    an_cert_unconfig_crl_auto_download();
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
    an_unix_time_t nbr_connect_triggered_time;
    uint16_t an_srvc_find_retry_count = 0;

    if (!an_bs_is_initialized()) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL,
                     "\n%sAutonomic Bootstrap process not initialized, "
                     "cant send Nbr Connect Message",
                     an_bs_pak);
        return;
    }

    nbr_connect_triggered_time = 
        an_unix_time_get_elapsed_time(nbr->selected_anr_reference_time);
    if (an_anra_is_configured()) {
        nbr->selected_anr_addr = an_anra_get_registrar_ip();
    } else if ((nbr_connect_triggered_time >= 
           AN_BS_MAX_WAIT_TIME_BEFORE_SELECTING_NEXT_ANR) || 
           (!an_addr_struct_comp(&nbr->selected_anr_addr, &AN_ADDR_ZERO))) {
        do {
            an_srvc_find_retry_count++;
            anra_ip = an_anr_get_ip_from_srvc_db();
            //if (an_test_get_number_of_anr_addr_from_pool() == 1) {
        }while (!an_addr_struct_comp(&anra_ip, &nbr->selected_anr_addr) &&
                an_srvc_find_retry_count < AN_SRVC_FIND_MAX_RETRY);

        if (an_srvc_find_retry_count >= AN_SRVC_FIND_MAX_RETRY) {
            DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
                "\n Same ANR service returned for more than %d times", 
                AN_SRVC_FIND_MAX_RETRY);
        }

        nbr->selected_anr_reference_time = 
                    an_unix_time_get_current_timestamp();
        nbr->selected_anr_addr = anra_ip;
    }

    if (an_addr_is_zero(nbr->selected_anr_addr)) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_SEVERE, NULL,
                     "\n%sSelected Autonomic Registrar IP is NULL, "
                     "cannot send Nbr Connect Message",
                     an_bs_pak);
        return;
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

    if (an_anra_is_live()) {
        /* I am ANRA, no need to forward the message */
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
