/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include "an.h"
#include "an_ni.h"
#include "an_nbr_db.h"
#include "../al/an_mem.h"
#include "an_event_mgr.h"
#include "an_msg_mgr.h"
#include "../al/an_if.h"
#include "../al/an_sudi.h"
#include "../al/an_addr.h"
#include "../al/an_cert.h"
#include "../al/an_timer.h"
#include "../al/an_logger.h"
#include "../al/an_ntp.h"
#include "an_bs.h"
#include "../al/an_str.h"
#include "../al/an_cert.h"

static uint8_t * an_ni_state_names[] = {
    "Neighbor Inside the Domain",
    "Neighbor Certificate Validation Failed",
    "Neighbor Outside the Domain",
};

extern const uint8_t *an_cert_enum_get_string(an_cert_api_ret_enum enum_type);

void an_ni_reset_cert_request_timer(an_nbr_t *nbr);
boolean an_ni_send_cert_request_message(an_nbr_t *nbr);
void an_ni_cert_reset(an_nbr_t *nbr);

boolean
an_ni_is_nbr_inside (an_nbr_t *nbr)
{
    if (!nbr || !nbr->udi.data || !nbr->udi.len) {
        return (FALSE);
    }

    return (nbr->ni_state == AN_NI_INSIDE);
}

boolean
an_ni_is_nbr_expired (an_nbr_t *nbr)
{
    if (!nbr || !nbr->udi.data || !nbr->udi.len) {
        return (FALSE);
    }

    return (nbr->validation.result == AN_CERT_VALIDITY_EXPIRED);

}

boolean
an_ni_is_nbr_outside (an_nbr_t *nbr)
{
    if (!nbr || !nbr->udi.data || !nbr->udi.len) {
        return (FALSE);
    }

    return (nbr->ni_state == AN_NI_OUTSIDE);
}

boolean
an_ni_is_nbr_revoked (an_nbr_t *nbr)
{
    if (!nbr || !nbr->udi.data || !nbr->udi.len) {
        return (FALSE);
    }
    return (nbr->validation.result == AN_CERT_VALIDITY_REVOKED);
}

void
an_ni_set_validation_result (an_nbr_t *nbr, an_cert_validation_result_e result)
{
    an_if_t nbr_ifhndl = 0;
    
    if (!nbr) {
        return;
    }

    if (!an_nbr_get_addr_and_ifs(nbr, NULL, &nbr_ifhndl, NULL)) {
        return;
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
             "\n%sNbr validation result %d %d", an_bs_event, 
             nbr->validation.result, result);

    if (nbr->validation.result != result) {
        nbr->validation.result = result;
        switch (result) {
        case AN_CERT_VALIDITY_PASSED:
             an_syslog(AN_SYSLOG_NBR_DOMAIN_CERT_VALID,
                  nbr->udi.data, an_if_get_name(nbr_ifhndl));   
        break;
        case AN_CERT_VALIDITY_EXPIRED:
             an_event_nbr_cert_in_validity_expired_state(nbr);
             an_syslog(AN_SYSLOG_NBR_DOMAIN_CERT_EXPIRED,
                  nbr->udi.data, an_if_get_name(nbr_ifhndl));   
        break;
        case AN_CERT_VALIDITY_REVOKED:
             an_syslog(AN_SYSLOG_NBR_DOMAIN_CERT_REVOKED,
                  nbr->udi.data, an_if_get_name(nbr_ifhndl));   
        break;
        case AN_CERT_VALIDITY_FAILED:
             an_event_nbr_cert_in_validity_expired_state(nbr);
             an_syslog(AN_SYSLOG_NBR_DOMAIN_CERT_INVALID,
                  nbr->udi.data, an_if_get_name(nbr_ifhndl));   
        break;
        default:
        break;
        }
    }
    return;
}

boolean
an_ni_set_state (an_nbr_t *nbr, an_ni_state_e state)
{
    if (!nbr) {
        return (FALSE);
    }
    
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
             "\n%sNbr state is %d %d", an_bs_event, nbr->ni_state, state);
    
    if (nbr->ni_state != state) {

        switch (state) {
        case AN_NI_INSIDE:
            an_event_nbr_inside_domain(nbr);
        break;
        case AN_NI_UNKNOWN:
        case AN_NI_CERT_EXPIRED:
        case AN_NI_OUTSIDE:
            an_bs_nbr_set_state(nbr, AN_NBR_BOOTSTRAP_NONE);
            an_event_nbr_outside_domain(nbr);
        break;
        default:
        break;
        }
        nbr->ni_state = state;
    }
    return (TRUE);
}

uint8_t *
an_ni_get_state_name (an_nbr_t *nbr)
{
    if (!nbr) {
        return (NULL);
    }

    return (an_ni_state_names[nbr->ni_state]);
}

void
an_ni_validate_with_crl (an_nbr_t *nbr)
{
    an_cert_validation_result_e result = AN_CERT_VALIDITY_UNKNOWN;
    an_ni_validate_context_t *udi_ctx = NULL;
    an_cert_t domain_cert = {};


    switch (nbr->cert_type) {
    case AN_NBR_CERT_DOMAIN_CERT:
        if (!an_tp_exists(AN_DOMAIN_TP_LABEL) 
            || !an_get_domain_cert(&domain_cert) 
            || !an_is_device_enrollment_url_set()) {
            an_ni_update_nbr_cert_validation_result(
                        AN_CERT_VALIDITY_UNKNOWN, nbr);        
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sNo domain certificate available",
                         an_bs_event);
            return;
        }
        nbr->last_validated_time =
                       an_unix_time_get_current_timestamp(); 
        udi_ctx =  (an_ni_validate_context_t *)an_malloc_guard(
                            sizeof(an_ni_validate_context_t), "AN NI UDI ctx");
        if (!udi_ctx) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sIn NI validate Malloc failed for validate ctx",
                         an_nd_event);
            return;
        }
        udi_ctx->save_udi.len = nbr->udi.len; 
        udi_ctx->save_udi.data =  (uint8_t *)an_malloc_guard(nbr->udi.len,
                                                    "AN NI Validated UDI");
        if (!udi_ctx->save_udi.data) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sIn NI validate Malloc failed for udi data in ctx",
                         an_nd_event);
            an_free_guard(udi_ctx);
            return;
        }
        an_memcpy_s(udi_ctx->save_udi.data, udi_ctx->save_udi.len, 
                                        nbr->udi.data, nbr->udi.len);
        result = an_cert_validate_with_revoke_check(
                                        &nbr->domain_cert, 
                                        (void *)udi_ctx);            
        if (result != AN_CERT_VALIDITY_PENDING) {
            if (udi_ctx) {
                if (udi_ctx->save_udi.data) {
                    an_free_guard(udi_ctx->save_udi.data);
                }
                an_free_guard(udi_ctx);
            }
        }

        an_ni_update_nbr_cert_validation_result(result, nbr);        
        break;
    case AN_NBR_CERT_SUDI: 

        an_ni_set_state(nbr, AN_NI_OUTSIDE);

        if (an_cert_validate_override_revoke_check(&nbr->sudi, AN_LOG_ND_EVENT)) {
            an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_PASSED);
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sNeighbor [%s] sudi cert validated", 
                         an_nd_event, nbr->udi.data);

        } else {
            an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_FAILED);
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sNeighbor [%s] sudi cert validation failed", 
                         an_nd_event, nbr->udi.data);
        }
        break;
    
    case AN_NBR_CERT_NONE:
    default:
        an_ni_set_state(nbr, AN_NI_OUTSIDE);
        an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_UNKNOWN);
        break;
    }
}

void
an_ni_validate (an_nbr_t *nbr)
{
    an_cert_validation_result_e result = AN_CERT_VALIDITY_UNKNOWN;
    an_cert_t domain_cert = {};

    switch (nbr->cert_type) {
    case AN_NBR_CERT_DOMAIN_CERT:
        if (!an_tp_exists(AN_DOMAIN_TP_LABEL)
            || !an_get_domain_cert(&domain_cert)) {
           an_ni_update_nbr_cert_validation_result(AN_CERT_VALIDITY_UNKNOWN,
                                                      nbr);
           DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sNo domain certificate available",
                         an_bs_event);
           return;
        }

        nbr->last_validated_time =
                       an_unix_time_get_current_timestamp(); 
        result = an_cert_validate_override_revoke_check(
                                        &nbr->domain_cert, 
                                        AN_LOG_BS_EVENT);                                
        an_ni_update_nbr_cert_validation_result(result, nbr);        
        break;
    case AN_NBR_CERT_SUDI: 

        an_ni_set_state(nbr, AN_NI_OUTSIDE);

        if (an_cert_validate_override_revoke_check(&nbr->sudi, AN_LOG_ND_EVENT)) {
            an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_PASSED);
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sNeighbor [%s] sudi cert validated", 
                         an_nd_event, nbr->udi.data);

        } else {
            an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_FAILED);
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sNeighbor [%s] sudi cert validation failed", 
                         an_nd_event, nbr->udi.data);
        }
        break;
    
    case AN_NBR_CERT_NONE:
    default:
        an_ni_set_state(nbr, AN_NI_OUTSIDE);
        an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_UNKNOWN);
        break;
    }
}


an_avl_walk_e
an_ni_validate_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    
    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }
    an_ni_validate(nbr);
    return (AN_AVL_WALK_SUCCESS);
}

boolean
an_ni_validate_nbrs (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
              "\n%sWalking the Nbr DB to validate the Nbr without crl",
                 an_nd_event);
    an_nbr_db_walk(an_ni_validate_cb, NULL);
    return (TRUE);
}

an_avl_walk_e
an_ni_validate_expired_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    
    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }
    if (nbr->validation.result == AN_CERT_VALIDITY_UNKNOWN ||
        nbr->validation.result == AN_CERT_VALIDITY_EXPIRED) {
        an_ni_validate(nbr);
    }
    return (AN_AVL_WALK_SUCCESS);
}

boolean
an_ni_validate_expired_nbrs (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
              "\n%sWalking the Nbr DB to validate expired Nbr without crl",
                 an_nd_event);
    an_nbr_db_walk(an_ni_validate_expired_cb, NULL);
    return (TRUE);
}

an_avl_walk_e
an_ni_validate_with_crl_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    
    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }
    if (nbr->domain_cert.data && nbr->domain_cert.len) {
        an_ni_validate_with_crl(nbr);
    }
    return (AN_AVL_WALK_SUCCESS);
}

boolean
an_ni_validate_with_crl_nbrs (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sWalking the Nbr DB to validate the Nbr with crl check",
                 an_nd_event);
    an_nbr_db_walk(an_ni_validate_with_crl_cb, NULL);
    return (TRUE);
}

void
an_ni_start_cert_request_timer (an_nbr_t *nbr)
{
    an_timer_start(&nbr->cert_request_timer, AN_NI_CERT_REQUEST_INTERVAL);
}

void
an_ni_stop_cert_request_timer (an_nbr_t *nbr)
{
    an_timer_stop(&nbr->cert_request_timer);
}

void
an_ni_reset_cert_request_timer (an_nbr_t *nbr)
{
    an_timer_reset(&nbr->cert_request_timer, AN_NI_CERT_REQUEST_INTERVAL);
}

void
an_ni_cert_revalidate_timer_start (an_nbr_t *nbr)
{
    if (an_timer_is_running(&nbr->cert_revalidate_timer)) {
        return;
    }

    an_timer_start(&nbr->cert_revalidate_timer, 
                   AN_NI_CERT_REVALIDATE_INTERVAL);    
}

void
an_ni_cert_revalidate_timer_stop (an_nbr_t *nbr)
{
    if (an_timer_is_running(&nbr->cert_revalidate_timer)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sStopping Nbr Revalidate Timer",
                  an_bs_event);
        an_timer_stop(&nbr->cert_revalidate_timer);
    }
}

void
an_ni_cert_reset (an_nbr_t *nbr)
{
    if (!nbr) {
        return;
    }

    nbr->cert_type = AN_NBR_CERT_NONE;

    if (nbr->domain_cert.data) {
        an_free_guard(nbr->domain_cert.data);
        nbr->domain_cert.data = NULL;
        nbr->domain_cert.len = 0;
    }
    if (nbr->sudi.data) {
        an_free_guard(nbr->sudi.data);
        nbr->sudi.data = NULL;
        nbr->sudi.len = 0;
    }
}

boolean
an_ni_cert_store (an_nbr_t *nbr, an_msg_interest_e interest, 
                  an_cert_t sudi, an_cert_t domain_cert)
{
    if (!nbr) {
        return (FALSE);
    }

    if (AN_CHECK_BIT_FLAGS(interest, AN_MSG_INT_SUDI)) {

        if (nbr->domain_cert.data) {
            an_free_guard(nbr->domain_cert.data);
        }
        nbr->domain_cert.data = NULL;
        nbr->domain_cert.len = 0;

        if (!an_cert_equal(sudi, nbr->sudi)) {
            if (nbr->sudi.data) {
                an_free_guard(nbr->sudi.data);
            }
            nbr->sudi.data = NULL;
            nbr->sudi.len = 0;

            if (sudi.len && sudi.data) {
                nbr->sudi.len = sudi.len;
                nbr->sudi.data = 
                            (uint8_t *)an_malloc_guard(sudi.len, "AN MSG SUDI");
                if (!nbr->sudi.data) {
                    return (FALSE);
                }
                an_memcpy_guard_s(nbr->sudi.data, nbr->sudi.len, 
                                            sudi.data, sudi.len);

                nbr->cert_type = AN_NBR_CERT_SUDI;

            } else {
                DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                             "\n%sNbr's Sudi cert is Null", an_nd_event);

                nbr->cert_type = AN_NBR_CERT_NONE;
            } 
        } else if (!(sudi.len && sudi.data)) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sNo Sudi Cert from Nbr [%s]", 
                         an_nd_event, nbr->udi.data);
            an_ni_start_cert_request_timer(nbr);
            nbr->cert_type = AN_NBR_CERT_NONE;
        }

    } else if (AN_CHECK_BIT_FLAGS(interest, AN_MSG_INT_DOMAIN_CERT)) {

        if (!an_cert_equal(domain_cert, nbr->domain_cert)) {
            if (nbr->domain_cert.data) {
                an_free_guard(nbr->domain_cert.data);
            }
            nbr->domain_cert.data = NULL;
            nbr->domain_cert.len = 0;

            if (domain_cert.len && domain_cert.data) {
                DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sIncoming NI cert and existing nbr cert are different",
                  an_bs_event);
                nbr->domain_cert.len = domain_cert.len;
                nbr->domain_cert.data = 
                    (uint8_t *)an_malloc_guard(domain_cert.len, "AN MSG Domain Cert");
                if (!nbr->domain_cert.data) {
                    return (FALSE);
                }
                an_memcpy_guard_s(nbr->domain_cert.data, nbr->domain_cert.len, 
                                        domain_cert.data, domain_cert.len);

                nbr->cert_type = AN_NBR_CERT_DOMAIN_CERT;
            } else {
                DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                             "\n%sNbr's [%s] domain cert is Null", an_nd_event, 
                             nbr->udi.data);

                nbr->cert_type = AN_NBR_CERT_NONE;
            }
        }else {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                  "\n%sIncoming NI cert and existing nbr cert are same",
                  an_bs_event);
        }

    } else {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNbr's [%s] cert is Null, reset Nbr Cert Timer", 
                     an_nd_event, nbr->udi.data);
        nbr->cert_type = AN_NBR_CERT_NONE;
        an_ni_reset_cert_request_timer(nbr);
    }

    return (TRUE);
}

boolean
an_ni_validate_cert_attributes (uint8_t *device_id, uint8_t *domain_id,
                                an_cert_t cert, an_udi_t message_udi)
{
    an_nbr_t *nbr = NULL;

    if (!cert.data && !cert.len) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNULL Input Params, cert", an_bs_event);
        return (FALSE);
    }

    if (!message_udi.data && !message_udi.len) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNULL Input Params, udi", an_bs_event);
        return (FALSE);
    }

    if (!domain_id && !device_id) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNULL Input Params, device_id, domain_id",
                     an_bs_event);
        return (FALSE);
        
    }
        
    nbr = an_nbr_db_search(message_udi);
    if (!nbr) {
        return (FALSE);
    }

    if (!an_cert_validate_subject_cn(cert, device_id)) {
            
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to validate the subject attr CN for "
                     " ND cert Response message", an_bs_event);
        return (FALSE);
        
    }
        
    if (!an_cert_validate_subject_ou(cert, domain_id)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to validate the subject attr OU for "
                     " ND cert Response message", an_bs_event);
        return (FALSE);
    }
        
    if (!an_cert_validate_subject_sn(cert, message_udi.data, 
                                           message_udi.len)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to validate the subject attr SN for "
                     " ND cert Response message", an_bs_event);
        return (FALSE);
    }

    return (TRUE);
}

boolean
an_ni_send_cert_request_message (an_nbr_t *nbr)
{
    an_msg_package *message = NULL;
    boolean res = FALSE;

    if (!nbr || !nbr->udi.data || !nbr->udi.len) {
        return (FALSE);
    }
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                "\n%sSend NI cert request to  Nbr", 
                     an_bs_event);

    message = an_msg_mgr_get_empty_message_package();
    if (!message) {
        return (FALSE);
    }

    an_msg_mgr_init_header(message, AN_PROTO_ACP, 
                           AN_MSG_ND_CERT_REQUEST);

    res = an_nbr_get_addr_and_ifs(nbr, &message->dest, &message->ifhndl, NULL);
    if (!res) {
        return (FALSE);
    }

    message->udi.data = (uint8_t *)an_malloc_guard(nbr->udi.len, "AN MSG UDI");
    if (!message->udi.data) {
        an_msg_mgr_free_message_package(message);
        return (FALSE);
    }
    message->udi.len = nbr->udi.len;
    an_memcpy_guard_s(message->udi.data, message->udi.len, nbr->udi.data, 
                                                      nbr->udi.len);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);

    an_msg_mgr_send_message(message);
    return (TRUE);
}

boolean
an_ni_cert_request (an_nbr_t *nbr)
{
    if (!nbr) {
        return (FALSE);
    }
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                "\n%sStart AN NI cert request to  Nbr %s", 
                     an_bs_event, nbr->udi.data);

    //an_ni_cert_reset(nbr);

    nbr->cert_request_retries = 0;
    an_ni_reset_cert_request_timer(nbr);
    
    return (an_ni_send_cert_request_message(nbr));
}

boolean
an_ni_cert_request_retry (an_nbr_t *nbr)
{
    if (!nbr) {
        return (FALSE);
    }

    if (nbr->cert_request_retries == AN_MAX_NI_RETRY_ATTEMPT) {
        nbr->cert_request_retries = 0;
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sMaximum retries of Cert Request to Nbr %s (%s) done", 
                     an_nd_event, nbr->device_id ? nbr->device_id : NULL,
                     nbr->udi.data);

        an_ni_validate(nbr);
        return (FALSE);
    }

    nbr->cert_request_retries++;
    an_ni_reset_cert_request_timer(nbr);
    
    return (an_ni_send_cert_request_message(nbr));
}

boolean
an_ni_send_cert_response_message (an_if_t ifhndl, an_addr_t ipaddr, 
                                  an_iptable_t iptable)
{
    an_msg_package *message = NULL;
    an_udi_t udi = {};
    an_cert_t sudi = {}, domain_cert = {};

    if (an_addr_is_zero(ipaddr) || !ifhndl) {
        return (FALSE);
    }

    an_sudi_get_cert(&sudi);
    if (an_get_domain_cert(&domain_cert))  {
        /*Check if domain cert is VALID- if invalid also send NI response 
         * with empty certificate and below bug id thrown */
         if (!domain_cert.valid) {
             DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL, 
                 "\n%sDomain cert invalid, Sending in NI cert "
                 "response to Nbr expired certificate", 
                 an_bs_event);
         }       
    }else {
         DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL, 
           "\n%sDomain cert is NULL, sending NULL NI response to Nbr %s", 
           an_bs_event, an_addr_get_string(&ipaddr));
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                "\n%sSend NI cert response to Nbr", 
                     an_bs_event);

    message = an_msg_mgr_get_empty_message_package();
    if (!message) {
        return (FALSE);
    }

    an_msg_mgr_init_header(message, AN_PROTO_ACP, 
                           AN_MSG_ND_CERT_RESPONSE);

    message->ifhndl = ifhndl;
    message->dest = ipaddr;
    message->iptable = iptable;

    if (!an_get_udi(&udi))  {
        an_msg_mgr_free_message_package(message);
        return (FALSE);
    }

    if (udi.data && udi.len) {
        message->udi.data = (uint8_t *)an_malloc_guard(udi.len, "AN MSG UDI");
        if (!message->udi.data) {
            an_msg_mgr_free_message_package(message);
            return (FALSE);
        }
        message->udi.len = udi.len;
        an_memcpy_guard_s(message->udi.data, message->udi.len, udi.data, udi.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);
    }

    if (domain_cert.data && domain_cert.len) {
        message->domain_cert.data = 
            (uint8_t *)an_malloc_guard(domain_cert.len, "AN MSG Domain Cert");
        if (!message->domain_cert.data) {
            an_msg_mgr_free_message_package(message);
            return (FALSE);
        }                       
        message->domain_cert.len = domain_cert.len;
        an_memcpy_guard_s(message->domain_cert.data, message->domain_cert.len, 
                                domain_cert.data, domain_cert.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DOMAIN_CERT);
    } else if (sudi.data && sudi.len) {
        message->sudi.data = (uint8_t *)an_malloc_guard(sudi.len, "AN MSG SUDI");
        if (!message->sudi.data) {
            an_msg_mgr_free_message_package(message);
            return (FALSE);
        }
        message->sudi.len = sudi.len;
        an_memcpy_guard_s(message->sudi.data, message->sudi.len, sudi.data, sudi.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_SUDI);

    } else {
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_SUDI);
    }

    an_msg_mgr_send_message(message);
    return (TRUE);
}

boolean
an_ni_incoming_cert_request (an_msg_package *message)
{
    if (!message || !message->udi.data || !message->udi.len) {
        an_msg_mgr_free_message_package(message);
        return (FALSE);
    }

    an_ni_send_cert_response_message(message->ifhndl, message->src, message->iptable); 

    an_msg_mgr_free_message_package(message);
    return (TRUE);
}

void    
an_ni_nbr_domain_cert_validated (an_nbr_t *nbr)
{
    if (nbr->validation.result == AN_CERT_VALIDITY_PASSED) {
        an_ni_start_nbr_cert_expire_timer(nbr);
    }
}

boolean
an_ni_incoming_cert_response (an_msg_package *message)
{
    an_nbr_t *nbr = NULL;
    an_cert_api_ret_enum result_old_cert_time = AN_CERT_INPUT_PARAM_INVALID;
    an_cert_api_ret_enum result_new_cert_time = AN_CERT_INPUT_PARAM_INVALID;
    an_unix_time_t new_validity_time = 0;
    an_unix_time_t old_validity_time = 0;
    an_unix_msec_time_t new_cert_validity_interval = 0;
    an_unix_msec_time_t old_cert_validity_interval = 0;
    an_unix_msec_time_t diff_in_validity_interval = 0;
    uint8_t new_validity_time_str[TIME_DIFF_STR];
    uint8_t old_validity_time_str[TIME_DIFF_STR];

    if (!message || !message->udi.data || !message->udi.len) {
        an_msg_mgr_free_message_package(message);
        return (FALSE);
    }

    nbr = an_nbr_db_search(message->udi); 
    if (!nbr) {
        an_msg_mgr_free_message_package(message);
        return (FALSE);        
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
                "\n%sRecvd AN NI cert response from  Nbr %s", 
                     an_bs_event, nbr->udi.data);

    if ((message->domain_cert.data != NULL) && 
        !an_ni_validate_cert_attributes(nbr->device_id,
                                        nbr->domain_id, 
                                        message->domain_cert, 
                                        message->udi)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sIncoming cert response's domain cert has "
                     "ummatched attributes(SN/OU/CN)", an_bs_event);
        an_msg_mgr_free_message_package(message);
        return (FALSE);
    }

    an_ni_stop_cert_request_timer(nbr);
   
    //The below check is for polling renewed certificate 
    if (nbr->domain_cert.data != NULL && message->domain_cert.data != NULL) {         
         result_old_cert_time = an_cert_get_cert_expire_time(&nbr->domain_cert, 
                               &old_cert_validity_interval, &old_validity_time);    
         an_unix_time_timestamp_conversion(old_validity_time, 
                                          old_validity_time_str);
         DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL, 
               "\n%sFrom nbr table cert validity time %s, valid interval %lld", 
                an_bs_event, old_validity_time_str, old_cert_validity_interval);

        //Determine expiry interval based on nbr certificate lifetime
        result_new_cert_time = an_cert_get_cert_expire_time(&message->domain_cert, 
                               &new_cert_validity_interval, &new_validity_time);    
        an_unix_time_timestamp_conversion(new_validity_time, 
                                          new_validity_time_str);
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%sNbr certificate new expiry time %s, new valid interval %lld",
                an_bs_event, new_validity_time_str, new_cert_validity_interval);
        if (result_new_cert_time == AN_CERT_API_SUCCESS && 
            result_old_cert_time == AN_CERT_API_SUCCESS) {
    
            if (old_cert_validity_interval <= new_cert_validity_interval)   {
                diff_in_validity_interval = new_cert_validity_interval - 
                                        old_cert_validity_interval;
            }
            if ( diff_in_validity_interval == 0 ) {
                //Both certificates are same
                DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sNbr certificates has not changed/renewed "
                    "diff in the cert validity time %lld",
                    an_bs_event, diff_in_validity_interval);
                an_ni_start_nbr_cert_expire_timer(nbr);
                an_msg_mgr_free_message_package(message);
                return (FALSE);
            } else if (diff_in_validity_interval > 0) {
                //Got new certificate - go ahead and validate new certificate 
                //Reset the cert poll count
                DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sNbr got a renewed certificate - diff in certificate "
                    "valid time %lld",
                     an_bs_event, diff_in_validity_interval);
                nbr->renew_cert_poll_count = 0;
                nbr->my_cert_expired_time = 0;
                nbr->renew_cert_5perc_poll_timer = 0;
                nbr->renew_cert_1perc_poll_timer = 0;
            } //end of if - Check of validity interval
        } //end of if - get cert validity time
    }//end of if - nbr domain cert exist 
    else {
       DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
            "\n%sNbr table has domain cert len %d, incoming NI mesg has " 
            "domain cert len %d",  an_bs_event, nbr->domain_cert.len,
            message->domain_cert.len);
       nbr->renew_cert_poll_count = 0;
       nbr->my_cert_expired_time = 0;        
       nbr->renew_cert_5perc_poll_timer = 0;
       nbr->renew_cert_1perc_poll_timer = 0;
    }

    if (!an_ni_cert_store(nbr, message->interest, 
                          message->sudi, message->domain_cert)) {
        an_msg_mgr_free_message_package(message);
        return (FALSE);
    }

    an_ni_validate(nbr);
    an_ni_nbr_domain_cert_validated(nbr);

    an_msg_mgr_free_message_package(message);
    return (TRUE);
}

void
an_ni_start_nbr_cert_expire_timer (an_nbr_t *nbr)
{
    an_unix_msec_time_t cert_validity_interval = 0;
    an_cert_api_ret_enum result;
    an_unix_time_t validity_time = 0;
    an_unix_msec_time_t perc_75 = 0;
    an_unix_time_t perc_5 = 0;
    an_unix_time_t perc_1 = 0;
    an_unix_time_t perc_40 = 0;
    uint8_t validity_time_str[TIME_DIFF_STR];
    an_unix_time_t expired_time_interval = 0;

    if (!nbr || !nbr->domain_cert.data) {
        return;
    }

    if (an_timer_is_running(&nbr->cert_expire_timer)) {
        return;
    }
 
    //Determine expiry interval based on nbr certificate lifetime
    result = an_cert_get_cert_expire_time(&nbr->domain_cert, 
                               &cert_validity_interval, &validity_time);    
    if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                  "\n%sUnable to obtain nbr certificate expiry time %s",
                  an_bs_event, an_cert_enum_get_string(result));
        return;
    }
    an_unix_time_timestamp_conversion(validity_time, 
                                           validity_time_str);

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
          "\n%sNbr certificate expiry countdown interval %lld, "
          "nbr cert is valid till %s", an_bs_event,
          cert_validity_interval, validity_time_str);
    

    if (cert_validity_interval > 0) {
        if (nbr->renew_cert_poll_count == 0) {
            an_cert_compute_cert_lifetime_percent(cert_validity_interval, 
                           &perc_5, &perc_1, &perc_40, &perc_75);
            nbr->renew_cert_5perc_poll_timer = perc_5;                
            nbr->renew_cert_1perc_poll_timer = perc_1;
            cert_validity_interval = perc_75;            
        } else {
            cert_validity_interval = nbr->renew_cert_5perc_poll_timer;
        } 

        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                    "\n%sNbr Poll attempt %d Started nbr cert poll timer %lld",
                     an_bs_event, 
                     nbr->renew_cert_poll_count, cert_validity_interval);
        
        an_timer_start64(&nbr->cert_expire_timer, cert_validity_interval);
        nbr->renew_cert_poll_count++;

    } else {
        if (nbr->my_cert_expired_time == 0) {
            nbr->my_cert_expired_time = 
                       an_unix_time_get_current_timestamp(); 
        }
        expired_time_interval = an_unix_time_get_elapsed_time(nbr->my_cert_expired_time);

        if (expired_time_interval < 
            AN_MAX_ALLOWED_TIME_NBR_IN_EXPIRED_STATE) { 
            //Continue to retain NBR as valid for 15 mins after expiry
            cert_validity_interval = nbr->renew_cert_1perc_poll_timer;
            an_timer_start64(&nbr->cert_expire_timer, cert_validity_interval);
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                   "\n%sNeighbor [%s] domain cert validation expired - "
                   "Nbr poll attempt %d time in expired state %ld", 
                   an_bs_event, nbr->udi.data, nbr->renew_cert_poll_count,
                   expired_time_interval);
            nbr->renew_cert_poll_count++;            
        } else {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE, NULL,
                   "\n%sNeighbor [%s] domain cert validation expired - "
                   "Nbr poll attempt %d- call Nbr cert validate API", 
                   an_bs_event, nbr->udi.data, nbr->renew_cert_poll_count);
            //PKI will mark this cert expired- few msec later 
            an_ni_validate(nbr);
        }
    }
}

void
an_ni_clean_and_refresh_nbr_cert (an_nbr_t *nbr)
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
an_ni_nbr_domain_cert_expired (an_nbr_t *nbr)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
             "\n%sNbr %s device cert is expired", an_bs_event, nbr->udi.data);
    an_ni_set_state(nbr, AN_NI_CERT_EXPIRED);
    an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_EXPIRED);
    an_ni_clean_and_refresh_nbr_cert(nbr);
}

void
an_ni_nbr_domain_cert_revoked (an_nbr_t *nbr)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
             "\n%sNbr %s device cert is revoked", an_bs_event, nbr->udi.data);
    an_ni_set_state(nbr, AN_NI_OUTSIDE);
    an_ni_set_validation_result(nbr, AN_CERT_VALIDITY_REVOKED);
}

void
an_ni_validation_cert_response_obtained (an_cert_validation_result_e status,
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
    an_ni_update_nbr_cert_validation_result(status, nbr);
}

void
an_ni_update_nbr_cert_validation_result (an_cert_validation_result_e result,
                        an_nbr_t *nbr)
{
    if (result == AN_CERT_VALIDITY_PASSED_WARNING) {
        if (nbr->validation.result == AN_CERT_VALIDITY_REVOKED) {
           DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNeighbor [%s] domain cert was earlier revoked"
                     " and now no CRL available to validate- keeping as revoked",
                     an_bs_event, nbr->udi.data);
           an_ni_nbr_domain_cert_revoked(nbr);
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
        an_ni_nbr_domain_cert_expired(nbr);
    } else if (result == AN_CERT_VALIDITY_REVOKED) {
        if (nbr->validation.result != AN_CERT_VALIDITY_EXPIRED) {
            an_ni_nbr_domain_cert_revoked(nbr);
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
