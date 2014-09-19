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

static uint8_t * an_ni_state_names[] = {
    "Neighbor Inside the Domain",
    "Neighbor Certificate Validation Failed",
    "Neighbor Outside the Domain",
};

boolean
an_ni_is_nbr_inside (an_nbr_t *nbr)
{
    if (!nbr || !nbr->udi.data || !nbr->udi.len) {
        return (FALSE);
    }

    return (nbr->ni_state == AN_NI_INSIDE);
}

boolean
an_ni_is_nbr_cert_expired (an_nbr_t *nbr)
{
    if (!nbr || !nbr->udi.data || !nbr->udi.len) {
        return (FALSE);
    }

    return (nbr->ni_state == AN_NI_CERT_EXPIRED);

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
an_ni_set_state (an_nbr_t *nbr, an_ni_state_e state)
{
    if (!nbr) {
        return (FALSE);
    }
    
    if (nbr->ni_state != state) {
        nbr->ni_state = state;

        switch (state) {
        case AN_NI_INSIDE:
            an_event_nbr_inside_domain(nbr);
        break;
        case AN_NI_UNKNOWN:
        case AN_NI_CERT_EXPIRED:
        case AN_NI_OUTSIDE:
            an_event_nbr_outside_domain(nbr);
        break;
        default:
        break;
        }
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
an_ni_validate (an_nbr_t *nbr) 
{
    an_cert_validation_result_e result;

    switch (nbr->cert_type) {
    case AN_NBR_CERT_DOMAIN_CERT :
        result = an_cert_validate(&nbr->domain_cert);
        if (result == AN_CERT_VALIDITY_PASSED) {
            if (nbr->validation.result == AN_CERT_VALIDITY_EXPIRED) {
                DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                             "\n%sNeighbor [%s] domain cert validated "
                             "after clock sync", an_nd_event, nbr->udi.data);
            } else {
                DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                             "\n%sNeighbor [%s] domain cert validated", 
                             an_nd_event, nbr->udi.data); 
            }

            an_ni_set_state(nbr, AN_NI_INSIDE);
            nbr->validation.result = AN_CERT_VALIDITY_PASSED;
            an_event_nbr_domain_cert_validated(nbr,TRUE);

        } else if (result == AN_CERT_VALIDITY_EXPIRED) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sNeighbor [%s] domain cert validation expired", 
                         an_nd_event, nbr->udi.data);

            an_ni_set_state(nbr, AN_NI_CERT_EXPIRED);
            nbr->validation.result = AN_CERT_VALIDITY_EXPIRED;
            an_event_nbr_domain_cert_validated(nbr,FALSE); 
        }
        else {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sNeighbor [%s] domain cert validation failed", 
                         an_nd_event, nbr->udi.data);
            an_ni_set_state(nbr, AN_NI_OUTSIDE);
            nbr->validation.result = AN_CERT_VALIDITY_FAILED;
            an_event_nbr_domain_cert_validated(nbr,FALSE);
        }
        break;
    case AN_NBR_CERT_SUDI: 

        an_ni_set_state(nbr, AN_NI_OUTSIDE);

        if (an_cert_validate(&nbr->sudi)) {
            nbr->validation.result = AN_CERT_VALIDITY_PASSED;
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sNeighbor [%s] sudi cert validated", 
                         an_nd_event, nbr->udi.data);

        } else {
            nbr->validation.result = AN_CERT_VALIDITY_FAILED;
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sNeighbor [%s] sudi cert validation failed", 
                         an_nd_event, nbr->udi.data);
        }
        break;
    
    case AN_NBR_CERT_NONE:
    default:
        an_ni_set_state(nbr, AN_NI_OUTSIDE);
        nbr->validation.result = AN_CERT_VALIDITY_UNKNOWN;
        break;
    }
}

an_walk_e
an_ni_validate_cb (an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    
    if (!nbr) {
        return (AN_WALK_FAIL);
    }

    an_ni_validate(nbr);
    return (AN_WALK_SUCCESS);
}

boolean
an_ni_validate_nbrs (void)
{
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sWalking the Nbr DB to validate the Nbr's identity",
                 an_nd_event);
    an_nbr_db_walk(an_ni_validate_cb, NULL);
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
                an_memcpy_guard(nbr->sudi.data, sudi.data, sudi.len);

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
                nbr->domain_cert.len = domain_cert.len;
                nbr->domain_cert.data = 
                    (uint8_t *)an_malloc_guard(domain_cert.len, "AN MSG Domain Cert");
                if (!nbr->domain_cert.data) {
                    return (FALSE);
                }
                an_memcpy_guard(nbr->domain_cert.data, domain_cert.data, 
                                domain_cert.len);

                nbr->cert_type = AN_NBR_CERT_DOMAIN_CERT;

            } else {
                DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                             "\n%sNbr's [%s] domain cert is Null", an_nd_event, 
                             nbr->udi.data);

                nbr->cert_type = AN_NBR_CERT_NONE;
            }
        }

    } else {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNbr's [%s] cert is Null, reset Nbr Cert Timer", 
                     an_nd_event, nbr->udi.data);
        nbr->cert_type = AN_NBR_CERT_NONE;
        //LS added here- Check with Ravi
        an_ni_reset_cert_request_timer(nbr);
    }

    return (TRUE);
}

boolean
an_ni_send_cert_request_message (an_nbr_t *nbr)
{
    an_msg_package *message = NULL;

    if (!nbr || !nbr->udi.data || !nbr->udi.len) {
        return (FALSE);
    }

    message = an_msg_mgr_get_empty_message_package();
    if (!message) {
        return (FALSE);
    }

    an_msg_mgr_init_header(message, AN_PROTO_ACP, 
                           AN_MSG_ND_CERT_REQUEST);

    an_nbr_get_addr_and_ifs(nbr, &message->dest, &message->ifhndl, NULL);

    message->udi.data = (uint8_t *)an_malloc_guard(nbr->udi.len, "AN MSG UDI");
    if (!message->udi.data) {
        an_msg_mgr_free_message_package(message);
        return (FALSE);
    }
    message->udi.len = nbr->udi.len;
    an_memcpy_guard(message->udi.data, nbr->udi.data, nbr->udi.len);
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

    an_ni_cert_reset(nbr);

    an_ni_validate(nbr);

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

    if (nbr->cert_request_retries == 2) {
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
    an_get_domain_cert(&domain_cert);

    message = an_msg_mgr_get_empty_message_package();

    an_msg_mgr_init_header(message, AN_PROTO_ACP, 
                           AN_MSG_ND_CERT_RESPONSE);

    message->ifhndl = ifhndl;
    message->dest = ipaddr;
    message->iptable = iptable;

    an_get_udi(&udi); 
    if (!udi.data || !udi.len) {
        return (FALSE);
    }

    if (udi.data && udi.len) {
        message->udi.data = (uint8_t *)an_malloc_guard(udi.len, "AN MSG UDI");
        if (!message->udi.data) {
            an_msg_mgr_free_message_package(message);
            return (FALSE);
        }
        message->udi.len = udi.len;
        an_memcpy_guard(message->udi.data, udi.data, udi.len);
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
        an_memcpy_guard(message->domain_cert.data, domain_cert.data, 
                        domain_cert.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DOMAIN_CERT);

    } else if (sudi.data && sudi.len) {
        message->sudi.data = (uint8_t *)an_malloc_guard(sudi.len, "AN MSG SUDI");
        if (!message->sudi.data) {
            an_msg_mgr_free_message_package(message);
            return (FALSE);
        }
        message->sudi.len = sudi.len;
        an_memcpy_guard(message->sudi.data, sudi.data, sudi.len);
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
        return (FALSE);
    }

    an_ni_send_cert_response_message(message->ifhndl, message->src, message->iptable); 

    an_msg_mgr_free_message_package(message);
    return (TRUE);
}

boolean
an_ni_incoming_cert_response (an_msg_package *message)
{
    an_nbr_t *nbr = NULL;

    if (!message || !message->udi.data || !message->udi.len) {
        return (FALSE);
    }

    nbr = an_nbr_db_search(message->udi); 
    if (!nbr) {
        return (FALSE);        
    }

    an_ni_stop_cert_request_timer(nbr);

    an_ni_cert_store(nbr, message->interest, 
                     message->sudi, message->domain_cert);

    an_ni_validate(nbr);

    an_msg_mgr_free_message_package(message);
    return (TRUE);
}
