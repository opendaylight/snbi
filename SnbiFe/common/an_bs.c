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

#define REJECTED_NBR_REFRESH_COUNT 6*10

boolean bs_initialized = FALSE;

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
    an_reset_anra_cert();

    bs_initialized = FALSE;
}

void 
an_bs_retrieve_saved_enrollment (void)
{
    uint8_t *tp_label = AN_DOMAIN_TP_LABEL;
    an_cert_t domain_ca_cert = {}, domain_device_cert = {};
    uint8_t *subject_cn = NULL, *device_name = NULL, 
            *domain_name = NULL, *name = NULL;
    uint16_t len = 0, device_name_len = 0, domain_name_len = 0;
    an_addr_t device_addr = AN_ADDR_ZERO;
    an_cert_api_ret_enum result;

    if (!an_bs_is_initialized()) {
        return;
    }

    result = an_cert_get_ca_cert_from_tp(tp_label, &domain_ca_cert);
    if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%s%s", an_bs_event, 
                     an_cert_enum_get_string(result));
        return;
    }
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sObtained CA Cert [%s] of Cert Len = %d from "
                 "Trustpoint: %s", an_bs_event, domain_ca_cert.data, 
                 domain_ca_cert.len, tp_label);

    result = an_cert_get_device_cert_from_tp(tp_label, &domain_device_cert);
    if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%s%s", an_bs_event, 
                     an_cert_enum_get_string(result));
        return;
    }
    
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sObtained Device Cert [%s] of Cert Len = %d from " 
                 "Trustpoint: %s", an_bs_event, domain_device_cert.data, 
                 domain_device_cert.len, tp_label);

    result = an_cert_get_subject_cn(domain_device_cert, &subject_cn, &len);
    if(result != AN_CERT_API_SUCCESS) {
       DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%s%s", an_bs_event, an_cert_enum_get_string(result));
       return;
    }

    name = an_strchr(subject_cn, DEVICE_DOMAIN_NAMES_DELIMITER);

    domain_name = name + 1;
    domain_name_len = an_strlen(domain_name);
    an_set_domain_id(domain_name);

    *name = '\0';
    device_name = subject_cn;
    device_name_len = an_strlen(device_name);
    an_set_device_id(device_name);

    device_addr = an_get_v6addr_from_names(domain_name, device_name);
    an_free_guard(device_name);
    an_set_device_ip(device_addr);

    an_set_anra_cert(domain_ca_cert);
    an_set_domain_cert(domain_device_cert);
        
    an_event_device_bootstrapped();
}

static boolean
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

    message->dest = an_get_anra_ip();
    message->iptable = an_get_iptable(); 
    message->src = an_ipv6_get_best_source_addr(message->dest, message->iptable);
    message->ifhndl = 0;

    an_msg_mgr_init_header(message, AN_PROTO_ACP, 
                           type);

    if (nbr->udi.len) {
        message->udi.data = (uint8_t *)an_malloc_guard(nbr->udi.len, "AN MSG UDI");
        if (!message->udi.data) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        } 
        message->udi.len = nbr->udi.len;
        an_memcpy_guard(message->udi.data, nbr->udi.data, nbr->udi.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);
    }

    if (nbr->sudi.len) {
        message->sudi.data = (uint8_t *)an_malloc_guard(nbr->sudi.len, "AN MSG sUDI");
        if (!message->sudi.data) {
            an_msg_mgr_free_message_package(message);            
            return (NULL);
        }
        message->sudi.len = nbr->sudi.len;
        an_memcpy_guard(message->sudi.data, nbr->sudi.data, nbr->sudi.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_SUDI);
    }

    if (nbr->domain_cert.len) {
        message->domain_cert.data = (uint8_t *)an_malloc_guard(nbr->domain_cert.len, "AN MSG domain cert");
        if (!message->domain_cert.data) {
            an_msg_mgr_free_message_package(message);
            return (NULL);
        }
        message->domain_cert.len = nbr->domain_cert.len;
        an_memcpy_guard(message->domain_cert.data, nbr->domain_cert.data, nbr->domain_cert.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DOMAIN_CERT);
    }

    message->device_id = (uint8_t *)an_malloc_guard(1+an_strlen(nbr->device_id), "AN MSG device id");
    if (!message->device_id) {
        an_msg_mgr_free_message_package(message);
        return (NULL);
    }
    an_memcpy_guard(message->device_id, nbr->device_id, 1+an_strlen(nbr->device_id));
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DEVICE_ID);

    message->domain_id = (uint8_t *)an_malloc_guard(1+an_strlen(nbr->domain_id), "AN MSG domain id");
    if (!message->domain_id) {
        an_msg_mgr_free_message_package(message);
        return (NULL);
    }
    an_memcpy_guard(message->domain_id, nbr->domain_id, 1+an_strlen(nbr->domain_id));
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DOMAIN_ID);

    an_nbr_get_addr_and_ifs(nbr, &message->if_ipaddr, NULL, NULL);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_IF_IPADDR);

    return (message);
}

void
an_bs_trigger_nbr_connect_message (an_nbr_t *nbr)
{
    an_msg_package *message = NULL;

    if (!an_bs_is_initialized()) {
        return;
    }

    if (an_addr_is_zero(an_get_anra_ip())) {
        return;
    }
   
    message = an_bs_prepare_message(nbr, AN_MSG_NBR_CONNECT); 
    if (!message) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
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

    if (!an_bs_is_initialized()) {
        return;
    }

    if (!nbr) {
        return;
    }

    my_domain_id = an_get_domain_id();
    if (!my_domain_id || !an_get_domain_cert(&domain_cert)) {
        /* I am not in a domain, cannot bootstrap my neighbor */
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sThis device is not part of the AN domain, "
                     "hence cant bootstrap the Nbr [%s]", 
                     an_bs_event, nbr->udi.data);
        return;
    }

    if (an_ni_is_nbr_inside(nbr)) {
        /* Neighbor and I are in the same domain, no need to bootstrap */
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNbr[%s] and this device already part of AN domain, "
                     "failed repeated bootstrap", an_bs_event, nbr->udi.data);
        return;
    } else if (an_bs_nbr_get_state(nbr) == AN_NBR_BOOTSTRAP_REJECTED) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNbr[%s] bootstrap state is AN_NBR_BOOTSTRAP_REJECTED, "
                     "can't bootstrap the Nbr", an_bs_event, nbr->udi.data);   
        if (nbr->rejected_nbr_refresh_count >= REJECTED_NBR_REFRESH_COUNT) {
            nbr->rejected_nbr_refresh_count = 0;
            an_bs_nbr_set_state(nbr, AN_NBR_BOOTSTRAP_NONE);
        } else {
            nbr->rejected_nbr_refresh_count++;
        }
        return;
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
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

    if (!an_bs_is_initialized()) {
        return (NULL);
    }
    
    if (!message) {
        return (NULL);
    }

    if (!message->udi.len || !message->udi.data) {
        return (NULL);
    }

    nbr = an_nbr_db_search(message->udi);

    if (!nbr) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNbr[%s] not found in NBR DB to forward the " 
                     "Message [%s], hence ignore it", an_bs_pak, 
                     message->udi.data, 
                     an_get_msg_name(message->header.msg_type)); 
        return (NULL);

    } else {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNbr[%s] found in the NBR DB, hence forwarding " 
                     "Message [%s] to Nbr", an_bs_pak, message->udi.data, 
                     an_get_msg_name(message->header.msg_type));

        an_nbr_get_addr_and_ifs(nbr, &message->dest, &message->ifhndl, NULL);

        message->iptable = nbr->iptable;
        an_addr_set_from_v6addr(&message->src, an_ipv6_get_ll(message->ifhndl));
        
        an_msg_mgr_send_message(message);
        return (nbr);
    }
}

boolean
an_bs_forward_message_to_anra (an_msg_package *message)
{
    if (!an_bs_is_initialized()) {
        return (FALSE);
    }

    if (an_anra_is_live()) {
        /* I am ANRA, no need to forward the message */
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                 "\n%sForwarding %s Message to Registrar",
                 an_bs_pak, an_get_msg_name(message->header.msg_type));
    message->src = AN_ADDR_ZERO;
    message->dest = an_get_anra_ip();
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
    an_log_type_e log;

    if (!an_bs_is_initialized()) {
        return;
    }

    if (!message) {
        return;
    }

    log = an_get_log_type(message->header.protocol_type, 
                          message->header.msg_type);

    an_set_domain_id(message->domain_id);
    an_set_device_id(message->device_id); 
    device_addr = an_get_v6addr_from_names(message->domain_id, message->device_id);
    an_set_device_ip(device_addr);
    an_set_anra_ip(message->anra_ipaddr);
    an_set_anra_if(message->ifhndl);
    an_set_anra_cert(message->anra_cert);

    result = an_cert_set_domain_ca_cert(message->anra_cert);
    if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(log, AN_DEBUG_MODERATE, NULL,
                     "\n%sFrom Booststrap Invite Registrar's cert, %s",
                     an_get_log_str(log), an_cert_enum_get_string(result));
        return;
    }
   
    an_bs_trigger_request_message(message);
    return;
}

void
an_bs_erase_unfinished_bootstrap (void)
{
    an_cert_t empty_cert = {};

    an_set_device_id(NULL);
    an_set_domain_id(NULL);
    an_set_domain_cert(empty_cert);
    an_set_anra_cert(empty_cert);
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
        return;
    }
    
    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                 "\n%sIncoming Bootstrap Message to enroll "
                 "quarantine device %s", an_bs_pak, message->udi.data);
    
    if (!message->udi.data || !message->udi.len ||
        !an_get_udi(&my_udi)) {
        an_msg_mgr_free_message_package(message);
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
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
        return;
    }

    if (!message->udi.data || !message->udi.len ||
        !an_get_udi(&my_udi)) {
        an_msg_mgr_free_message_package(message);
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
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

    if (!an_bs_is_initialized()) {
        return;
    }

    if (!message->udi.data || !message->udi.len ||
        !an_get_udi(&my_udi)) {
        return;
    }

    if ((message->udi.len == my_udi.len) &&
        !an_memcmp(message->udi.data, my_udi.data, my_udi.len)) {
        /* Message to me, proceed with processing */

    } else if ((nbr = an_bs_forward_message_to_nbr(message))) {
        /* Message to my neighbor, forwarded it */
        if (nbr && !an_ni_is_nbr_inside(nbr)) {
            an_bs_nbr_set_state(nbr, AN_NBR_BOOTSTRAP_STARTED);
            return;
        }
        return;

    } else {
        /* Message not to me & not to my neighbors, drop it */
         DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                      "\n%sMessage [%s] is neither to my neighbors or to me",
                      an_bs_pak, an_get_msg_name(message->header.msg_type));
        return;
    }

    if (an_anra_is_configured() && 
        !an_addr_equal(&message->dest, &message->src)) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice has a locally configured AN Registrar, "
                     "ignoring the invite message from the other devices",
                     an_bs_pak);
        return;
    } 

    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                 "\n%sIncoming Message [%s] is for me[%s]", an_bs_pak, 
                 an_get_msg_name(message->header.msg_type), an_get_device_id());

    an_get_domain_cert(&domain_cert);
    if (domain_cert.len && domain_cert.data) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sDevice[%s] has domain cert already part of domain, "
                     "ignoring the %s message", an_bs_pak, my_udi.data,
                     an_get_msg_name(message->header.msg_type));
        return;
    }

    if (!an_msg_mgr_verify_anra_signature(message, message->anra_cert)) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sSignature validation of BS Invite failed", an_bs_pak);
        return;
    }

    if (message->masa_sign.len) {
        if (!(an_smime_reply_verify_and_extract(message->masa_sign.data, 
                                                masa_trustpoint,
                                                &data_extract, &data_len))) {
            an_log(AN_LOG_MASA | AN_LOG_BS, "\nMASA verification failed");
            return;
        } else { 
            if (NULL == an_strstr(data_extract, "PID:")) {
                an_log(AN_LOG_MASA | AN_LOG_BS, "\nFailed to parse MASA response");
                return;
            } else {
                an_log(AN_LOG_MASA | AN_LOG_BS, 
                        "\nMASA message verified, continuing with bootstrap");
            }
        }
        AN_CLEAR_BIT_FLAGS(message->interest, AN_MSG_INT_MASA_SIGN);
    } else {
        an_log(AN_LOG_MASA | AN_LOG_BS, "\nMASA signature not present continuing ");
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

    if (!an_bs_is_initialized()) {
        return;
    }

    if (!response) {
        return;
    }

    if (!response->udi.data || !response->udi.len ||
        !an_get_udi(&my_udi)) {
        return;
    }

    if ((response->udi.len == my_udi.len) &&
        !an_memcmp(response->udi.data, my_udi.data, my_udi.len)) {
        /* Message to me, proceed with processing */

    } else if (an_bs_forward_message_to_nbr(response)) {
        /* Message to my neighbor, forwarded it */
        return;

    } else {
        /* Message not to me & not to my neighbors, drop it */
         DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                      "\n%sMessage [%s] is neither to my neighbors or to me",
                      an_bs_pak, an_get_msg_name(response->header.msg_type));
        return;
    }

    if (an_anra_is_configured() && 
        !an_addr_equal(&response->dest, &response->src)) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice has a locally configured AN Registrar, "
                     "ignoring the invite message from the other devices",
                     an_bs_pak);
        return;
    } 

    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                 "\n%sReceived Domain Cert from AN Registrar", an_bs_pak);   
    an_get_domain_cert(&domain_cert);
    if (domain_cert.len && domain_cert.data) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice [%s] already bootstrapped, ignoring repeated "
                     "Bootstrap Response Message", an_bs_pak, my_udi.data);
        an_msg_mgr_free_message_package(response);
	    return;
    }

    an_set_domain_cert(response->domain_cert); 
        
    result = an_cert_set_domain_device_cert(response->domain_cert);
    if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sWith the incoming Bootstrap Response's domain cert, "
                     "%s", an_bs_pak, an_cert_enum_get_string(result));
        return;
    }

    an_msg_mgr_free_message_package(response);

    an_config_save();
    an_event_device_bootstrapped();
}

void
an_bs_trigger_request_message (an_msg_package *invite)
{
    uint8_t *key_label = AN_DOMAIN_KEY_LABEL; 
    an_key_t public_key = {};
    an_cert_req_t pkcs10 = {};
    an_sign_t pkcs10_sign = {};
    an_msg_package *bs_request = NULL;
    uint8_t *device_name = NULL;
    uint8_t *domain_name = NULL;
    an_cert_api_ret_enum result;

    if (!an_bs_is_initialized()) {
        return;
    }

    device_name = an_get_device_id();
    domain_name = an_get_domain_id();

    if (!device_name || !domain_name) {
        return;
    }

    bs_request = an_msg_mgr_get_empty_message_package();    
    if (!bs_request) {
        return;
    }

    public_key = an_get_public_key(key_label);
    if (!public_key.len || !public_key.data) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sWhile triggerring Bootstrap Request Message, "
                     "failed to generate AN domain keypair", an_bs_pak);
        return;
    }
    
    result = an_cert_generate_request(key_label, device_name, domain_name, &pkcs10, &pkcs10_sign);
    if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sWhile triggerring Bootstrap Request Message, %s",
                     an_bs_pak, an_cert_enum_get_string(result));
        return;
    }

    bs_request->header.ver = 1;
    bs_request->header.msg_type = AN_MSG_BS_REQUEST;
    bs_request->header.hop_limit = 255;

    bs_request->udi.len = invite->udi.len;
    bs_request->udi.data = (uint8_t *)an_malloc_guard(invite->udi.len, "AN MSG UDI");
    if (!bs_request->udi.data) {
        an_msg_mgr_free_message_package(bs_request);
        return;
    }
    an_memcpy_guard(bs_request->udi.data, invite->udi.data, invite->udi.len);
    AN_SET_BIT_FLAGS(bs_request->interest, AN_MSG_INT_UDI);

    bs_request->cert_request = pkcs10; 
    AN_SET_BIT_FLAGS(bs_request->interest, AN_MSG_INT_CERT_REQ);

    bs_request->cert_req_sign = pkcs10_sign;
    AN_SET_BIT_FLAGS(bs_request->interest, AN_MSG_INT_CERT_REQ_SIGN);

    bs_request->public_key.len = public_key.len;
    bs_request->public_key.data = (uint8_t *)an_malloc_guard(public_key.len, "AN MSG Public Key");
    if (!bs_request->public_key.data) {
        an_msg_mgr_free_message_package(bs_request);
        return;
    } 
    an_memcpy_guard(bs_request->public_key.data, public_key.data, public_key.len);
    AN_SET_BIT_FLAGS(bs_request->interest, AN_MSG_INT_PUB_KEY);

    bs_request->src = invite->dest;
    bs_request->dest = invite->src;
    bs_request->iptable = an_get_iptable();
    bs_request->ifhndl = invite->ifhndl;
    
    an_msg_mgr_send_message(bs_request);
}
