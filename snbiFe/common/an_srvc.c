/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#define AN_SRVC_NBR_REFRESH_INTERVAL (5*1000)
#define AN_SRVC_MAX_RETRIES 10

#include "an_ni.h"
#include "an_nbr_db.h"
#include "an_srvc.h"
#include "an_acp.h"
#include "../al/an_types.h"
#include "../al/an_timer.h"
#include "../al/an_sudi.h"
#include "../al/an_mem.h"
#include "../al/an_str.h"
#include "../al/an_misc.h"
#include "../al/an_aaa.h"
#include "an_event_mgr.h"
#include "../al/an_ntp.h"

an_timer an_generictimer = {0};

static const uint8_t *an_srvc_type_s[] = {
    "AAA Service",
    "None",
};

const uint8_t *
an_get_srvc_type_str(an_service_type_e srvc_type) 
{
    return (an_srvc_type_s[srvc_type]);
}

void
an_srvc_nbr_donot_expect_ack (an_nbr_t *nbr,
                      an_service_info_t *srvc_info, boolean sync_done)
{

    an_service_type_e srvc_type = srvc_info->srvc_type;
    an_nbr_service_info_t *nbr_srvc_info = NULL;
    int indicator = 0;

    if ((srvc_type < AN_SERVICE_AAA) || (srvc_type>=AN_SERVICE_MAX)) {
       an_log(AN_LOG_SRVC,"\n%sInvalid Service type", an_srvc_prefix);
       return;
    }

    nbr_srvc_info = &(nbr->an_nbr_srvc_list[srvc_type]);

    an_log(AN_LOG_SRVC, 
            "\n%sNbr sync_done %d srvc_ip  %s nbr_srvc_ip %s sync_done %d",
            an_srvc_prefix, nbr_srvc_info->sync_done, 
            an_addr_get_string(&srvc_info->srvc_ip),
            an_addr_get_string(&nbr_srvc_info->srvc_ip), sync_done);
    an_memcmp_s(&srvc_info->srvc_ip, sizeof(an_addr_t), &nbr_srvc_info->srvc_ip,
                                                 sizeof(an_addr_t), &indicator);
    if (nbr_srvc_info->sync_done == FALSE) {
      if ((sync_done == FALSE) || ((indicator == 0) && (sync_done == TRUE))) {
          an_log(AN_LOG_SRVC, 
                  "\n%sNo longer expecting Autonomic Registrar service-info ACK from %s",
                  an_srvc_prefix, nbr->udi.data);
            nbr_srvc_info->retries_done = 0;
            nbr_srvc_info->sync_done = sync_done;
            an_timer_stop(&nbr_srvc_info->cleanup_timer);
       } else {
          an_log(AN_LOG_SRVC, 
                 "\n%sStill expecting Autonomic Registrar service-info ACK from %s",
                 an_srvc_prefix, nbr->udi.data);
       }
    } else {
          an_log(AN_LOG_SRVC, 
                 "\n%sSync already done with nbr %s",
                 an_srvc_prefix, nbr->udi.data);
    }

}

void
an_srvc_nbr_expect_ack (an_nbr_t *nbr, 
                      an_service_info_t *srvc_info)
{
    an_service_type_e srvc_type = srvc_info->srvc_type;
    an_nbr_service_info_t *nbr_srvc_info = NULL;

    if (!nbr) {
       an_log(AN_LOG_SRVC,"\n%sNULL nbr pointer", an_srvc_prefix);
       return;
    }

    if (srvc_type < AN_SERVICE_AAA || srvc_type >= AN_SERVICE_MAX) {
        an_log(AN_LOG_SRVC, "\n%sInvalid service type", an_srvc_prefix);
    }

    nbr_srvc_info = &nbr->an_nbr_srvc_list[srvc_type]; 

    an_log(AN_LOG_SRVC, "\n%sExpecting Service-Info ACK in %d sec", 
            an_srvc_prefix, AN_SRVC_NBR_REFRESH_INTERVAL/1000);

    an_timer_start(&nbr_srvc_info->cleanup_timer, 
                                     AN_SRVC_NBR_REFRESH_INTERVAL);
    an_memcpy_s((uint8_t *)&nbr_srvc_info->srvc_ip, sizeof(an_addr_t),
               (uint8_t *)&srvc_info->srvc_ip, 
               sizeof(an_addr_t));
    nbr_srvc_info->sync_done = FALSE;
}

void 
an_srvc_nbr_ack_timer_expired (an_nbr_t *nbr, an_timer_e timer_type)
{
    an_nbr_service_info_t *nbr_srvc_info;
    an_service_info_t srvc_info;
    an_service_type_e srvc_type;
    if (!nbr) {
        return;
    }
    
    srvc_type = timer_type - AN_TIMER_TYPE_AAA_INFO_SYNC + AN_SERVICE_AAA; 
    an_log(AN_LOG_SRVC,"\n%sAN Service Nbr ACK timer expired for service %d",
            an_srvc_prefix, srvc_type);

    if (srvc_type<AN_SERVICE_AAA || srvc_type >= AN_SERVICE_MAX) {
       an_log(AN_LOG_SRVC,"\n%sInvalid service type", an_srvc_prefix);
       return;
    }
    srvc_info.srvc_type = srvc_type;
    nbr_srvc_info = &nbr->an_nbr_srvc_list[srvc_type];
    an_memcpy_s((uint8_t *)&srvc_info.srvc_ip, sizeof(an_addr_t),
                (uint8_t *)&nbr_srvc_info->srvc_ip,sizeof(an_addr_t));

    if (nbr_srvc_info->retries_done == AN_SRVC_MAX_RETRIES) {
        nbr_srvc_info->retries_done = 0;
        an_log(AN_LOG_SRVC, "\n%sMax Service Info retries to nbr: '%s' done", 
                an_srvc_prefix, nbr->udi.data);
        return;
    }

    nbr_srvc_info->retries_done++;
    an_log(AN_LOG_SRVC,"\n%sService Info retries done till now %d",
            an_srvc_prefix, nbr_srvc_info->retries_done);
   
    an_log(AN_LOG_SRVC,"\n%sResend SRVC info send to nbr %s",
            an_srvc_prefix, nbr->udi);
    an_srvc_send_message(nbr->udi, &srvc_info);
}

an_avl_walk_e
an_srvc_flood_halt_cb (an_avl_node_t *node, void *args)
{
    an_service_info_t *srvc_info = (an_service_info_t *)args;
    an_nbr_t *nbr = (an_nbr_t *)node;

    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }
    an_log(AN_LOG_SRVC,"\n%sHalting ack timer for nbr %s, Service Info "
            "type %d, IP %s", an_srvc_prefix, nbr->udi.data, 
            srvc_info->srvc_type, an_addr_get_string(&srvc_info->srvc_ip)); 
    an_srvc_nbr_donot_expect_ack(nbr, srvc_info, FALSE);
    return (AN_AVL_WALK_SUCCESS);

}

void
an_srvc_flood_halt (an_service_info_t *srvc_info)
{
    an_log(AN_LOG_SRVC, "\n%sHalting current Service-Info messages "
            "& ACK timers Service type %d IP %s", an_srvc_prefix,
            srvc_info->srvc_type, an_addr_get_string(&srvc_info->srvc_ip)); 
    an_nbr_db_walk(an_srvc_flood_halt_cb, (void *)srvc_info);

}


an_avl_walk_e
an_srvc_flood_cb(an_avl_node_t *node, void *args)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    an_service_info_t *srvc_info = (an_service_info_t *)args;
    an_service_type_e srvc_type = srvc_info->srvc_type;
    an_nbr_service_info_t *nbr_srvc_info = NULL;
    int indicator = 0;

    an_log(AN_LOG_SRVC, "\n%sIn Service flood callback, Service Type "
            " %d, IP %s", an_srvc_prefix, srvc_info->srvc_type,
            an_addr_get_string(&srvc_info->srvc_ip)); 

    if (!nbr) {
        an_log(AN_LOG_SRVC,"\n%sNUll neighbor pointer", an_srvc_prefix);
        return (AN_AVL_WALK_FAIL);
    }

    if (srvc_type < AN_SERVICE_AAA || srvc_type >= AN_SERVICE_MAX) {
        an_log(AN_LOG_SRVC, "\n%sInvalid service type", an_srvc_prefix);
       return (AN_AVL_WALK_FAIL);
    }

    nbr_srvc_info = &nbr->an_nbr_srvc_list[srvc_type];
    an_memcmp_s(&nbr_srvc_info->srvc_ip, sizeof(an_addr_t), &srvc_info->srvc_ip,
                                                 sizeof(an_addr_t), &indicator);
    if (indicator == 0) {
       if (nbr_srvc_info->sync_done == TRUE) {
           an_log(AN_LOG_SRVC, 
                  "\n%sNbr %s has same Autonomic Registrar info so not sending",
                  an_srvc_prefix, nbr->udi.data);
           return (AN_AVL_WALK_SUCCESS);
        } else {
           an_log(AN_LOG_SRVC,"\n%sReset retries for nbr to zero", 
                   an_srvc_prefix);
           nbr_srvc_info->retries_done = 0;
        }
    }
    an_log(AN_LOG_SRVC,"\n%sIP mismatch my service IP %s nbr service IP %s",
            an_srvc_prefix, an_addr_get_string(&srvc_info->srvc_ip),
            an_addr_get_string(&nbr_srvc_info->srvc_ip));
    an_log(AN_LOG_SRVC,"\n%sResend SRVC info to nbr %s",
                an_srvc_prefix, nbr->udi);
    an_srvc_send_message(nbr->udi, srvc_info);
    return (AN_AVL_WALK_SUCCESS);

}

void
an_srvc_flood (an_service_info_t *srvc_info)
{
    an_srvc_flood_halt(srvc_info);

    an_log(AN_LOG_SRVC, "\n%sFlooding Service-Info Ack type %d, IP %s",
            an_srvc_prefix, srvc_info->srvc_type,
            an_addr_get_string(&srvc_info->srvc_ip));
    an_nbr_db_walk(an_srvc_flood_cb, (void *)srvc_info);

}


void
an_srvc_receive (an_service_info_t *srvc_info, an_udi_t src_udi)
{
    an_udi_t my_udi = {};
    an_nbr_t *nbr = NULL;
    int indicator = 0;


//    if (!strcmp("UNKNOWN", an_addr_get_string(&srvc_info->srvc_ip))) {
    if ((srvc_info->srvc_type < AN_SERVICE_AAA) 
                && (srvc_info->srvc_type > AN_SERVICE_MAX)) {       
        
        an_log(AN_LOG_SRVC, "\n%sInvalid Service Info Type %d IP %s from %s", 
                an_srvc_prefix, srvc_info->srvc_type, 
                an_addr_get_string(&srvc_info->srvc_ip), src_udi.data);
        return;
    }

    an_log(AN_LOG_SRVC, "\n%sReceived Service Info type %d IP %s from %s", 
            an_srvc_prefix, srvc_info->srvc_type, 
            an_addr_get_string(&srvc_info->srvc_ip), src_udi.data);

    nbr = an_nbr_db_search(src_udi);
    if (nbr) {
        /* Service Info from a neighbor */
       if (an_ni_is_nbr_inside(nbr)) {
          an_log(AN_LOG_SRVC,"\n%sNbr inside domain - set sevice info "
                  "and send ack", an_srvc_prefix);
          an_nbr_set_service_info(nbr, srvc_info);
          an_srvc_send_ack_message(srvc_info, nbr);
       } else {
          an_log(AN_LOG_SRVC,"\n%sNbr not inside ignoring message", an_srvc_prefix);
       }
    } else {
        if (!an_get_udi(&my_udi)) {
            return;
        }
        if (!my_udi.len) {
            return;
        }
        an_memcmp_s(src_udi.data, AN_UDI_MAX_LEN, my_udi.data, my_udi.len, &indicator);
        if ((src_udi.len != my_udi.len) || indicator) {
            /* Service Info  from an unknown device, drop it */
            an_log(AN_LOG_SRVC, "\n%sDropping service info from an unknown nbr",
                    an_srvc_prefix);
            return;
        }
    }
   
    an_log(AN_LOG_SRVC, "\n%sSetting service type %d Service IP: %s", 
            an_srvc_prefix, srvc_info->srvc_type, 
            an_addr_get_string(&srvc_info->srvc_ip));
    an_set_service_info(srvc_info->srvc_type, &srvc_info->srvc_ip); 
    an_srvc_inject(srvc_info->srvc_type, &srvc_info->srvc_ip);
    an_srvc_enable(srvc_info->srvc_type, &srvc_info->srvc_ip);
}

void
an_srvc_ack_receive (an_service_info_t *srvc_info, an_udi_t src_udi)
{
    an_nbr_t *nbr = NULL;

    nbr = an_nbr_db_search(src_udi);
    if (!nbr) {
        return;
    }

    an_log(AN_LOG_SRVC, "\n%sReceived Service Info ACK type %d from udi %s IP %s", 
            an_srvc_prefix, srvc_info->srvc_type, src_udi.data, 
            an_addr_get_string(&srvc_info->srvc_ip));
    
    an_srvc_nbr_donot_expect_ack (nbr,srvc_info, TRUE);
}

void
an_srvc_inject (an_service_type_e srvc_type, an_addr_t* srvc_ip)
{
    an_service_info_t srvc_info;
    an_log(AN_LOG_SRVC, "\n%sInjecting service info type %d IP %s", 
            an_srvc_prefix, srvc_type, an_addr_get_string(srvc_ip));    

    srvc_info.srvc_type = srvc_type;

    an_memcpy_s((uint8_t *)&srvc_info.srvc_ip, sizeof(an_addr_t), 
                            (uint8_t *)srvc_ip, sizeof(an_addr_t));
    an_srvc_flood(&srvc_info);
}

void
an_srvc_enable (an_service_type_e srvc_type, an_addr_t* srvc_ip)
{
    an_aaa_param_t aaa_param = {{0}};

    switch (srvc_type) {
    case AN_SERVICE_AAA:
        if (an_acp_is_initialized()) {
            an_memcpy_s((uint8_t *)&aaa_param.address, sizeof(an_addr_t), 
                                              srvc_ip, sizeof(an_addr_t));
            an_aaa_update(&aaa_param);
        }
        break;
    default:
        break;
    }
}

void
an_srvc_incoming_message (an_msg_package *srvc_msg)
{
    an_log(AN_LOG_SRVC, "\n%sIncoming Service Info Mesage", an_srvc_prefix);
    
    an_msg_mgr_log_message(srvc_msg, AN_LOG_NONE);
    
    an_srvc_receive(&srvc_msg->srvc_info, srvc_msg->udi);

    an_log(AN_LOG_SRVC,"\n%sFreeing Service Info Message", 
            an_srvc_prefix);
    an_msg_mgr_free_message_package(srvc_msg);

}

void
an_srvc_incoming_ack_message (an_msg_package *srvc_ack_msg)
{
    an_log(AN_LOG_SRVC, "\n%sIncoming Service Info Ack Mesage", an_srvc_prefix);
    
    an_msg_mgr_log_message(srvc_ack_msg, AN_LOG_NONE);
    
    an_srvc_ack_receive(&srvc_ack_msg->srvc_info, srvc_ack_msg->udi);
    
    an_log(AN_LOG_SRVC,"\n%sFreeing Service Info Ack Message", an_srvc_prefix);
    an_msg_mgr_free_message_package(srvc_ack_msg);
}

void
an_srvc_send_message (an_udi_t nbr_udi, an_service_info_t *srvc_info)
{
    an_msg_package *srvc_info_msg = NULL;
    an_nbr_t *nbr = NULL;
    an_udi_t my_udi = {};

    nbr = an_nbr_db_search(nbr_udi);
    if (!nbr) {
        return;
    }
   
    if (!an_get_udi(&my_udi)) {
        return;
    }

    srvc_info_msg = an_msg_mgr_get_empty_message_package(); 
    if (!srvc_info_msg) {
        return;
    }

    an_log(AN_LOG_SRVC, "\n%sSending Service Info type %s on IP: %s to nbr %s",
            an_srvc_prefix, an_get_srvc_type_str(srvc_info->srvc_type), 
            an_addr_get_string(&srvc_info->srvc_ip), nbr->udi.data);

    an_msg_mgr_init_header(srvc_info_msg, AN_PROTO_ACP, 
                           AN_MSG_SERVICE_INFO);

    srvc_info_msg->udi.len = my_udi.len;
    srvc_info_msg->udi.data = (uint8_t *)an_malloc_guard(my_udi.len,
                                                         "AN Service Info MSG UDI");
    if (!srvc_info_msg->udi.data) {
        an_msg_mgr_free_message_package(srvc_info_msg);
        return;
    }
    an_memcpy_guard_s(srvc_info_msg->udi.data, srvc_info_msg->udi.len, 
                                        my_udi.data, my_udi.len);
    AN_SET_BIT_FLAGS(srvc_info_msg->interest, AN_MSG_INT_UDI);

    srvc_info_msg->srvc_info.srvc_type  = srvc_info->srvc_type;
    an_memcpy_guard_s(&srvc_info_msg->srvc_info.srvc_ip, sizeof(an_addr_t),
                             &srvc_info->srvc_ip, sizeof(an_addr_t));
    AN_SET_BIT_FLAGS(srvc_info_msg->interest, AN_MSG_INT_SERVICE_INFO);

    srvc_info_msg->dest = an_get_v6addr_from_names(nbr->domain_id, 
                                    "aaaa.bbbb.cccc", nbr->device_id); 
    srvc_info_msg->iptable = an_get_iptable();
    srvc_info_msg->ifhndl = 0;
    srvc_info_msg->src = AN_ADDR_ZERO;
    
    an_msg_mgr_log_message(srvc_info_msg, AN_LOG_NONE);

    an_msg_mgr_send_message(srvc_info_msg);

    an_srvc_nbr_expect_ack (nbr, srvc_info);
}

void
an_srvc_send_all_to_nbr (an_udi_t nbr_udi)
{
   an_service_info_t aaa_info;

   aaa_info.srvc_type = AN_SERVICE_AAA;
   aaa_info.srvc_ip = an_get_aaa_ip();

   if (!an_addr_is_zero(aaa_info.srvc_ip)) {
       an_log(AN_LOG_SRVC,"\n%sSending AAA IP %s", 
               an_srvc_prefix, an_addr_get_string(&aaa_info.srvc_ip));
       an_srvc_send_message(nbr_udi, &aaa_info);
   }
}


void
an_srvc_send_ack_message (an_service_info_t *srvc_info, an_nbr_t *nbr)
{
    an_msg_package *ack = NULL;
    an_udi_t my_udi = {};

    if (!nbr) {
        return;
    }
   
    ack = an_msg_mgr_get_empty_message_package(); 
    if (!ack) {
        return;
    }

    if (!an_get_udi(&my_udi)) {
        an_msg_mgr_free_message_package(ack);
        return;
    }

    an_log(AN_LOG_SRVC, "\n%sSending Service Info ACK type %d  IP %s to nbr %s", 
            an_srvc_prefix, srvc_info->srvc_type, 
            an_addr_get_string(&srvc_info->srvc_ip), nbr->udi.data);

    an_msg_mgr_init_header(ack, AN_PROTO_ACP, 
                           AN_MSG_SERVICE_INFO_ACK);

    ack->udi.len = my_udi.len;
    ack->udi.data = (uint8_t *)an_malloc_guard(my_udi.len,"Service Info Ack");
    if (!ack->udi.data) {
        an_msg_mgr_free_message_package(ack);
        return;
    }
    an_memcpy_guard_s(ack->udi.data, ack->udi.len, my_udi.data, my_udi.len);
    AN_SET_BIT_FLAGS(ack->interest, AN_MSG_INT_UDI);

    ack->srvc_info.srvc_type  = srvc_info->srvc_type;
    an_memcpy_guard_s((uint8_t *)&ack->srvc_info.srvc_ip, sizeof(an_addr_t),
                         (uint8_t *)&srvc_info->srvc_ip, sizeof(an_addr_t));
    AN_SET_BIT_FLAGS(ack->interest, AN_MSG_INT_SERVICE_INFO);

    ack->dest = an_get_v6addr_from_names(nbr->domain_id,"aaaa.bbbb.cccc", nbr->device_id); 
    ack->iptable = an_get_iptable();
    ack->ifhndl = 0;
    ack->src = AN_ADDR_ZERO;
    
    an_msg_mgr_log_message(ack, AN_LOG_NONE);

    an_msg_mgr_send_message(ack);
}


/*----------------------Service Event handling-----------------------*/

void
an_srvc_event_service_received (void *context, int value)
{
    an_srvc_srv_ctx_t *srv_ctx = NULL;
    an_srvc_srv_t *srv_data = NULL;
    an_srvc_srv_t srv_wd_data = {0};
    an_srvc_host_t *host_rec = NULL;

    uint16_t input_invalid = FALSE;

    if (NULL == context) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
                 "\n%sNull service context received", an_srvc_event);
        return;
    }

    srv_ctx = (an_srvc_srv_ctx_t *)context;
    input_invalid = an_srvc_validate_servicename(srv_ctx->serName);
    input_invalid += an_srvc_validate_regType(srv_ctx->regType);
    input_invalid += an_srvc_validate_domain(srv_ctx->domain);

    if (input_invalid) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
            "%sInvalid Service Instance : Invalid string length ",
                an_srvc_event);
        an_mem_chunk_free(&an_srvc_srv_ctx_pool, srv_ctx);
        return;
    }

    if (value == SERVICE_ADD) {
        srv_ctx = (an_srvc_srv_ctx_t *)context;
        srv_data = an_srvc_add_srv_record(srv_ctx);
        if (srv_data && an_acp_is_initialized()) {
            if (srv_data->serviceRef) {
                an_DNSServiceRefDeallocate(srv_data->serviceRef);
                srv_data->serviceRef = 0;
            }
            an_service_resolve(srv_data->serName, srv_data->regType,
                        srv_data->domain, srv_data);

        }

        an_mem_chunk_free(&an_srvc_srv_ctx_pool, srv_ctx);
    } else {
        /* Reflect this withdrawl on all autonomic interfaces, so that the neighbor
           who might have learnt service from this interface clears the service */
        an_service_reflect_on_interfaces(srv_ctx);
        an_strcpy(srv_wd_data.serName, AN_DISC_SER_NAME_LEN, srv_ctx->serName);
        an_strcpy(srv_wd_data.regType, AN_SERVICE_TYPE_MAX_LEN, srv_ctx->regType);
        an_strcpy(srv_wd_data.domain, AN_DISC_DOMAIN_NAME_LEN, srv_ctx->domain);

        srv_data = an_srvc_srv_db_search(an_srvc_ptr[srv_ctx->service_type].an_srvc_srv,
                        srv_ctx->serName, srv_ctx->regType, srv_ctx->domain);

        if (srv_data == NULL) {
            an_mem_chunk_free(&an_srvc_srv_ctx_pool, srv_ctx);
            return;
        }

        if (0 != an_strnlen(srv_data->hostName, AN_DISC_HOSTNAME_LEN)) {
            host_rec = an_srvc_host_db_search(an_srvc_host_db, srv_data->hostName);
            if (host_rec != NULL) {
                /* Remove the srv db, so that we dont get this when we pick up the service*/
                an_srvc_srv_db_remove (an_srvc_ptr[srv_ctx->service_type].an_srvc_srv, &srv_wd_data);
                an_srvc_db_walk(host_rec->an_aaaa_db, an_srvc_notify_service_cb,
                        (void *)&srv_ctx->service_type);
            }
        }

        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sWithdrawn AAA service",
                    an_srvc_event);
        an_mem_chunk_free(&an_srvc_srv_ctx_pool, srv_ctx);
    }

}

void
an_srvc_event_service_resolved (void *context, int value)
{
    an_srvc_host_ctx_t *host_ctx = NULL;
    an_srvc_host_t *host_data = NULL;
    an_srvc_srv_t *srv_data = NULL;

    uint16_t input_invalid = FALSE;

    if (NULL == context) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
                 "\n%sNull host context received", an_srvc_event);
        return;
    }

    host_ctx = (an_srvc_host_ctx_t *)context;
    input_invalid = an_srvc_validate_servicename(host_ctx->serName);
    input_invalid += an_srvc_validate_regType(host_ctx->regType);
    input_invalid += an_srvc_validate_domain(host_ctx->domain);
    input_invalid += an_srvc_validate_host(host_ctx->hostName);

    if (input_invalid) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
            "%sInvalid Service Instance : Invalid string length ",
                an_srvc_event);
        an_mem_chunk_free(&an_srvc_host_ctx_pool, host_ctx);
        return;
    }

    host_ctx = (an_srvc_host_ctx_t *)context;
    srv_data = an_srvc_srv_db_search(an_srvc_ptr[host_ctx->service_type].an_srvc_srv,
                    host_ctx->serName, host_ctx->regType, host_ctx->domain);
    if (srv_data == NULL) {
        an_mem_chunk_free(&an_srvc_host_ctx_pool, host_ctx);
        return;
    }

    if (!an_srvc_update_srv_record(srv_data, host_ctx, value)) {
        srv_data->serviceRef = 0;
        an_mem_chunk_free(&an_srvc_host_ctx_pool, host_ctx);
        return;
    }

    host_data = an_srvc_host_db_search(an_srvc_host_db, srv_data->hostName);
    if (host_data == NULL) {
        host_data = an_srvc_host_alloc_node();
        if (host_data == NULL) {
            an_mem_chunk_free(&an_srvc_host_ctx_pool, host_ctx);
            return;
        }
        an_srvc_host_db_insert(an_srvc_host_db, host_data, srv_data->hostName);
        an_srvc_db_create(&(host_data->an_aaaa_db));
        srv_data->host_ptr = host_data;
    } else if (host_data->serviceRef) {
        DEBUG_AN_LOG (AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
                "\n This service is already getting resolved , not triggering again");
        an_mem_chunk_free(&an_srvc_host_ctx_pool, host_ctx);
        srv_data->host_ptr = host_data;
        return;
        //an_DNSServiceRefDeallocate(host_data->serviceRef);
        //host_data->serviceRef = 0;
    } else {
        srv_data->host_ptr = host_data;
    }

    host_data->resolved_time = an_unix_time_get_current_timestamp();
    if (an_acp_is_initialized() && !(host_data->serviceRef)) {
        an_host_resolve(host_data, srv_data->ifIndex);
    }

    an_mem_chunk_free(&an_srvc_host_ctx_pool, host_ctx);
}

void
an_srvc_event_host_resolved (void *context, int value)
{
    an_srvc_aaaa_ctx_t *aaaa_ctx = NULL;
    an_srvc_host_t *host_data = NULL;
    an_srvc_aaaa_t *aaaa_data = NULL;
    an_srvc_aaaa_t aaaa_rec = {{0}};

    uint16_t input_invalid = FALSE;

    if (NULL == context) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
                 "\n%sNull AAAA context received", an_srvc_event);
        return;
    }

    aaaa_ctx = (an_srvc_aaaa_ctx_t *)context;
    input_invalid += an_srvc_validate_host(aaaa_ctx->hostName);

    if (input_invalid) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
            "%sInvalid host resolve : Invalid string length ",
                an_srvc_event);
        an_mem_chunk_free(&an_srvc_aaaa_ctx_pool, aaaa_ctx);
        return;
    }

    aaaa_ctx = (an_srvc_aaaa_ctx_t *)context;
    host_data = an_srvc_host_db_search(an_srvc_host_db, aaaa_ctx->hostName);
    if (host_data == NULL) {
        an_mem_chunk_free(&an_srvc_aaaa_ctx_pool, aaaa_ctx);
        return;
    }

    if (value == SERVICE_ADD) {
        host_data->resolved_time = an_unix_time_get_current_timestamp();
        aaaa_data = an_srvc_aaaa_db_search(host_data->an_aaaa_db, &(aaaa_ctx->address));
        if (aaaa_data == NULL) {
            aaaa_data = an_srvc_aaaa_alloc_node();
            if (aaaa_data == NULL) {
                //host_data->serviceRef = 0;
                an_mem_chunk_free(&an_srvc_aaaa_ctx_pool, aaaa_ctx);
                return;
            }

            an_srvc_aaaa_db_insert(host_data->an_aaaa_db, aaaa_data, &(aaaa_ctx->address));
        }

        aaaa_data->resolved_time = an_unix_time_get_current_timestamp();
        an_srvc_notify_address_change(aaaa_data->address, value);
    } else {
        an_memcpy(&(aaaa_rec.address), &(aaaa_ctx->address), sizeof(an_addr_t));

        /* Before notifying service withdrawl remove the data from the db */
        an_srvc_aaaa_db_remove(host_data->an_aaaa_db, &aaaa_rec);

        //an_srvc_notify_address_change(aaaa_ctx->address, value);
        if (an_list_is_empty(host_data->an_aaaa_db)) {
            if (host_data->serviceRef) {
                an_DNSServiceRefDeallocate(host_data->serviceRef);
            }
            an_srvc_host_db_remove(an_srvc_host_db, host_data);
        }
    }

    an_mem_chunk_free(&an_srvc_aaaa_ctx_pool, aaaa_ctx);
}

void
an_srvc_srv_received_event_handler (void *context)
{
    an_event_service_discovery_info_t *srv_context = NULL;

    if(!context) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle service event ");
        return;
    }
    srv_context = (an_event_service_discovery_info_t *)context;
    an_srvc_event_service_received(srv_context->context, srv_context->value);
}

void
an_srvc_srv_resolved_event_handler (void *context)
{
    an_event_service_discovery_info_t *srv_context = NULL;

    if(!context) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle service event ");
        return;
    }
    srv_context = (an_event_service_discovery_info_t *)context;
    an_srvc_event_service_resolved(srv_context->context, srv_context->value);
}

void
an_srvc_host_resolved_event_handler (void *context)
{
    an_event_service_discovery_info_t *srv_context = NULL;

    if(!context) {
         DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid context to handle service event ");
        return;
    }
    srv_context = (an_event_service_discovery_info_t *)context;
    an_srvc_event_host_resolved(srv_context->context, srv_context->value);
}

void
an_srvc_generic_timer_expired_event_handler (void *info_ptr)
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

        an_strcpy(anr_param.ca_type, AN_CA_SERVER_LEN, 
                    an_anra_get_ca_type_name());
        an_service_announce(AN_ANR_SERVICE, an_anr_get_servcie_name(), anr_ip,
                            &anr_param, an_source_if);
        an_free(anr_param.ca_type);
    }

    an_srvc_db_expire();
    an_timer_start(&an_generictimer, AN_GENERIC_TIMER_INTERVAL);
    return;
}

void
an_srvc_anr_shut_event_handler (void *info_ptr)
{
    an_service_withdraw(AN_ANR_SERVICE, an_anr_get_servcie_name(),
                        an_source_if);
}

void
an_srvc_acp_uninit_event_handler (void *info_ptr)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAutonomic Control Plane Uninitialized", an_bs_event);
    an_service_stop();
    return;
}

void
an_srvc_acp_init_event_handler (void *info_ptr)
{
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAAA/Syslog services initialized", an_bs_event);

    an_service_start();
}

void
an_srvc_acp_on_link_removed_event_handler (void *link_info_ptr)
{
    an_nbr_t *nbr = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    an_if_t nbr_ifhndl = 0;
    an_if_t ifhndl = 0;
    an_nbr_link_context_t *nbr_link_ctx = NULL;

    if (!link_info_ptr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr link info is NULL, Cant handle acp link removal event", 
                an_bs_event);
        return;
    }

    nbr_link_ctx = (an_nbr_link_context_t *)link_info_ptr;

    if (nbr_link_ctx == NULL)
    {
       DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sContext is NULL in acp on link removed event", an_nd_event);
       return;
    }

    nbr = nbr_link_ctx->nbr;
    nbr_link_data = nbr_link_ctx->nbr_link_data;
     
    if (!nbr || !nbr_link_data) {
        return;
    }
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
an_srvc_acp_on_link_created_event_handler (void *link_info_ptr)
{
    an_nbr_t *nbr = NULL;
    an_nbr_link_spec_t *nbr_link_data = NULL;
    an_if_t ifhndl = 0;
    an_nbr_link_context_t *nbr_link_ctx = NULL;

    if (!link_info_ptr) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\n%sNbr link info is NULL, Cant handle acp link removal event", 
                an_bs_event);
        return;
    }

    nbr_link_ctx = (an_nbr_link_context_t *)link_info_ptr;
    if (nbr_link_ctx == NULL)
    {
       DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sContext is NULL in acp on link created event", 
                    an_nd_event);
       return;
    }

    nbr = nbr_link_ctx->nbr;
    nbr_link_data = nbr_link_ctx->nbr_link_data;

    if (!nbr  || !nbr->udi.len || !nbr_link_data) {
        return;
    }

    an_srvc_send_all_to_nbr(nbr->udi);

    ifhndl = an_acp_get_acp_if_on_nbr_link(nbr, nbr_link_data);
    /* Enable service discovery on interface */
    if (ifhndl) {
        an_sd_cfg_if_commands(ifhndl, TRUE);
        an_discover_services(ifhndl);
    }
}

void
an_srvc_udi_available_event_handler (void *info_ptr)
{
    an_udi_t my_udi = {};

    if (!an_get_udi(&my_udi)) {
        return;
    }
    an_sd_cfg_global_commands(TRUE);
    an_srvc_db_init();
    an_timer_start(&an_generictimer, AN_GENERIC_TIMER_INTERVAL);
}

void
an_srvc_anr_uninit_event_handler (void *info_ptr)
{
     an_service_withdraw(AN_ANR_SERVICE, an_anr_get_servcie_name(), 0);
}
/*--------------------AN SD register for event handlers ---------------------*/
void
an_srvc_register_for_events (void) 
{
    an_event_register_consumer(AN_MODULE_SERVICE_DISCOVERY,
                        AN_EVENT_SD_SRVC_RECEIVED, 
                        an_srvc_srv_received_event_handler);
    an_event_register_consumer(AN_MODULE_SERVICE_DISCOVERY,
                        AN_EVENT_SD_SRVC_RESOLVED, 
                        an_srvc_srv_resolved_event_handler);
    an_event_register_consumer(AN_MODULE_SERVICE_DISCOVERY,
                        AN_EVENT_SD_HOST_RESOLVED, 
                        an_srvc_host_resolved_event_handler);
    an_event_register_consumer(AN_MODULE_SERVICE_DISCOVERY,
                        AN_EVENT_TIMER_GENERIC_EXPIRED, 
                        an_srvc_generic_timer_expired_event_handler);
    an_event_register_consumer(AN_MODULE_SERVICE_DISCOVERY,
                        AN_EVENT_ANR_SHUT, an_srvc_anr_shut_event_handler);
    an_event_register_consumer(AN_MODULE_SERVICE_DISCOVERY,
                        AN_EVENT_ACP_UNINIT, an_srvc_acp_uninit_event_handler);
    an_event_register_consumer(AN_MODULE_SERVICE_DISCOVERY,
                        AN_EVENT_ACP_INIT, an_srvc_acp_init_event_handler);
    an_event_register_consumer(AN_MODULE_SERVICE_DISCOVERY,
                        AN_EVENT_ACP_ON_LINK_REMOVED, 
                        an_srvc_acp_on_link_removed_event_handler);
    an_event_register_consumer(AN_MODULE_SERVICE_DISCOVERY,
                        AN_EVENT_ACP_ON_LINK_CREATED, 
                        an_srvc_acp_on_link_created_event_handler);
    an_event_register_consumer(AN_MODULE_SERVICE_DISCOVERY,
                        AN_EVENT_UDI_AVAILABLE, 
                        an_srvc_udi_available_event_handler);
    an_event_register_consumer(AN_MODULE_SERVICE_DISCOVERY,
                        AN_EVENT_ANR_UNINIT, an_srvc_anr_uninit_event_handler);
}



