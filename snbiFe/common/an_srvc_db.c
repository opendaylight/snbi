/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "an_srvc_db.h"
#include "an_event_mgr.h"
#include "an_anra.h"
#include "../al/an_timer.h"
#include "../al/an_addr.h"
#include "../al/an_avl.h"
#include "../al/an_mem.h"
#include "../al/an_logger.h"
#include "../al/an_str.h"
#include "../al/an_aaa.h"
#include "../al/an_syslog.h"
#include "../al/an_ntp.h"
#include "../al/an_misc.h"
#include "an_nd.h"
#include "an_acp.h"
#include "../al/an_cert.h"

an_addr_t autoip_sd_param_global;
extern uint16_t an_sha1_length;

an_srvc_aaaa_t *an_srvc_aaaa_alloc_node (void)
{
    an_srvc_aaaa_t *aaaa_data = NULL;

    aaaa_data = an_malloc_guard(sizeof(an_srvc_aaaa_t),
                    "AN AAAA record");
    if (aaaa_data == NULL) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                     "\n%sMemory Alloc failed for the service AAAA DB entry", an_srvc_event);
        return (FALSE);
    }

    an_memset(aaaa_data, 0, sizeof(an_srvc_aaaa_t));
    return (aaaa_data);
}

an_srvc_host_t *an_srvc_host_alloc_node (void)
{
    an_srvc_host_t *host_data = NULL;
    
    host_data = an_malloc_guard(sizeof(an_srvc_host_t),
                    "AN Host record");
    if (host_data == NULL) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                     "\n%sMemory Alloc failed for the service Host DB entry", an_srvc_event);
        return (FALSE);
    }
    
    an_memset_guard(host_data, 0, sizeof(an_srvc_host_t));
    return (host_data);
}   

an_srvc_srv_t * an_srvc_db_alloc_node (void)
{
    an_srvc_srv_t *srv_data = NULL;

    srv_data = an_malloc_guard(sizeof(an_srvc_srv_t),
                                      "AN PTR record");
    if (srv_data == NULL) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                     "\n%sMemory Alloc failed for the service SRV DB entry", an_srvc_event);
        return (NULL);
    }

    an_memset_guard(srv_data, 0 , sizeof(an_srvc_srv_t));
    srv_data->magic_num = 0x00ABCDEF;
    return (srv_data);
}

void
an_srvc_free_aaaa_node (an_srvc_aaaa_t *aaaa_data)
{
    an_free_guard(aaaa_data);
}

void
an_srvc_free_host_node (an_srvc_host_t *host_data)
{
    an_free_guard(host_data);
}

void
an_srvc_free_srv_node (an_srvc_srv_t *srv_data)
{
    /* TODO Free the srv_data in the list */
    an_free_guard(srv_data);
}

an_cerrno
an_srvc_aaaa_node_remove (an_list_t *list, const an_list_element_t *current,
                    an_srvc_aaaa_t *aaaa_data)
{
    an_addr_t used_address = {0};
    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%s Removing AAAA record from Host DB",
                        an_srvc_event);
    used_address = aaaa_data->address;

    if (!an_list_remove(list, (an_list_element_t *)current, aaaa_data)) {
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    } else {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%s Successfully removed Node from AAAA DB",
                        an_srvc_event);
        an_srvc_free_aaaa_node(aaaa_data);
    }

    an_srvc_notify_address_change(used_address, SERVICE_REMOVE);
    return (AN_CERR_SUCCESS);
}

an_cerrno
an_srvc_host_node_remove (an_list_t *list, const an_list_element_t *current,
                    an_srvc_host_t *host_data)
{
    if ((NULL == list) || (NULL == current) || (NULL == host_data)) {
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    if (host_data->serviceRef != 0) {
        an_DNSServiceRefDeallocate(host_data->serviceRef);
    }

    an_srvc_unlink_srvc_instance_from_host_db(host_data); 
    if (host_data->an_aaaa_db) {
        an_list_destroy(&host_data->an_aaaa_db);
    }

    if (!an_list_remove(list, (an_list_element_t *)current, host_data)) {
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    } else {
        DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%s Successfully removed Node from Srvc PTR DB",
                        an_srvc_event);
        an_srvc_free_host_node(host_data);
    }
    
    return (AN_CERR_SUCCESS);
}

an_cerrno
an_srvc_db_walk (an_list_t *list, an_list_walk_handler callback_func,
                     void *srv_data)
{
    an_cerrno ret;
    //walk the list and pass the list elem to the callback func
    ret = AN_CERR_POSIX_ERROR(an_list_walk(list,
                callback_func,
                srv_data));
    return (ret);
}

boolean
an_srvc_db_create (an_list_t **ptr_data)
{
    if (!(*ptr_data)) {
        if (AN_CERR_SUCCESS != an_list_create(ptr_data,
                              "AN Srvc DB")) {
            DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sSrvc DB creation failed",
                         an_srvc_event);
            return (FALSE);
        }
        else {
            DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sSrvc DB created succesfully",
                         an_srvc_event);
            return (TRUE);
        }
    }
    return (TRUE);
}

static an_cerrno
an_srvc_remove_and_free_all_aaaa_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_srvc_aaaa_t *curr_data = NULL;
    an_cerrno ret = AN_CERR_SUCCESS;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params to remove link in the "
                     "Srvc AAAA DB", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    curr_data = (an_srvc_aaaa_t *)current->data;
    if (list && current) {
        ret = an_srvc_aaaa_node_remove(list, current, curr_data);

        return ret;
    }
    
    return (AN_CERR_V_FATAL(0, 0, EINVAL));
}


static an_cerrno
an_srvc_remove_and_free_all_host_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_srvc_host_t *curr_data = NULL;
    an_cerrno ret = AN_CERR_SUCCESS;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params to remove link in the "
                     "Srvc Host DB", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    curr_data = (an_srvc_host_t *)current->data;
    if (list && current) {
        an_srvc_db_walk(curr_data->an_aaaa_db, an_srvc_remove_and_free_all_aaaa_cb,
                              NULL);
         /* TODO Need to destroy an_aaaa_db list from host node*/
        ret = an_srvc_host_node_remove(list, current, curr_data);
        return ret;
    }

    return (AN_CERR_V_FATAL(0, 0, EINVAL));
}

static an_cerrno
an_srvc_remove_and_free_all_nodes_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_srvc_srv_t *curr_data = NULL;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params to remove link in the "
                     "Srvc PTR DB", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }
    
    curr_data = (an_srvc_srv_t *)current->data;
    if (list && current) {
        if (curr_data->serviceRef != 0) {
            an_DNSServiceRefDeallocate(curr_data->serviceRef);
        }
        
        if (!an_list_remove(list, (an_list_element_t *)current, curr_data))
        {
            return (AN_CERR_V_FATAL(0, 0, EINVAL));
        } else {
            DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%s Successfully removed Node from SRV DB",
                    an_srvc_event);
            an_srvc_free_srv_node(curr_data);
        }
    }
    return (AN_CERR_V_FATAL(0, 0, EINVAL));
}

an_cerrno
an_srvc_aaaa_db_destroy (an_list_t *list)
{
    an_cerrno ret;
    /* 
     * Walk list of AAAA db and free all memory 
    */
     DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sWalking the AAAA DB to destroy all the srvc info",
                 an_srvc_event);

    ret = an_srvc_db_walk(list, an_srvc_remove_and_free_all_aaaa_cb,
                              NULL); 

    return (ret);
}

an_cerrno
an_srvc_host_db_destroy (an_list_t *list)
{
    an_cerrno ret;
    /* 
     * Walk list of host db and free all memory 
    */

    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
     "\n%sWalking the HOST DB to destroy all the srvc info",
                 an_srvc_event);

    ret = an_srvc_db_walk(list, an_srvc_remove_and_free_all_host_cb,
                              NULL);

    if (an_list_is_valid(list)) {
         ret = an_list_destroy(&list);
         if (AN_CERR_SUCCESS != ret) {
             DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                          "\n%sHost DB destroy failed",
                          an_srvc_event);
         } else {
             DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                          "\n%sHost DB destroy successful",
                          an_srvc_event);
             list = NULL;
         }
    }

    return (ret);
}

an_cerrno
an_srvc_srv_db_destroy (an_list_t *list)
{
    an_cerrno ret;
    /* 
     * Walk list of SRV db and free all memory including AAAA records
    */

    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sWalking the PTR DB to destroy all the srvc info",
                 an_srvc_event);

    ret = an_srvc_db_walk(list, an_srvc_remove_and_free_all_nodes_cb,
                              NULL);

    if (an_list_is_valid(list)) {
         ret = an_list_destroy(&list);
         if (AN_CERR_SUCCESS != ret) {
             DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                          "\n%sSRV DB destroy failed",
                          an_srvc_event);
         } else {
             DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                          "\n%sSRV DB destroy successful",
                          an_srvc_event);
             list = NULL;
         }
    }

    return (ret);
}

boolean
an_srvc_aaaa_db_insert (an_list_t *list, an_srvc_aaaa_t *aaaa_data,
                    an_addr_t *address)
{

    if (address == NULL) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%s Address parameter invalid", an_srvc_event);
        return (FALSE);
    }

    if (!an_list_is_valid(list)) {
       DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid Srvc AAAA DB", an_srvc_event);
       return (FALSE);
    }

    an_memcpy(&aaaa_data->address, address, sizeof(an_addr_t));

    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                  "\n%s Adding Srvc AAAA Node to the DB"
                    " with address %s", an_srvc_event,
                    an_addr_get_string(address));

    an_list_enqueue_node(list, aaaa_data);

    return (TRUE);
}

boolean
an_srvc_host_db_insert (an_list_t *list, an_srvc_host_t *host_data,
        uint8_t *hostName)
{
    if (an_srvc_validate_host(hostName)) {
        return (FALSE);
    }

    if (!an_list_is_valid(list)) {
       DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid Srvc AAAA DB", an_srvc_event);
       return (FALSE);
    }

    an_strcpy(host_data->hostName, AN_DISC_HOSTNAME_LEN, hostName);

    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                  "\n%s Adding Srvc AAAA Node to the DB", an_srvc_event);

    an_list_enqueue_node(list, host_data);

    return (TRUE);
    }

boolean
an_srvc_srv_db_insert (an_list_t *list, an_srvc_srv_t *srv_data,
        an_service_type_t service_type,
        uint8_t *serName,
        uint8_t *regType, uint8_t *domain)
{
    uint16_t input_invalid = 0;

    input_invalid = an_srvc_validate_servicename(serName);
    input_invalid += an_srvc_validate_regType(regType);
    input_invalid += an_srvc_validate_domain(domain);
    input_invalid += an_srvc_validate_srvc_type(service_type);

    if (input_invalid) {
        return (FALSE);
    }

    if (!an_list_is_valid(list)) {
       DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid Srvc Srv DB", an_srvc_event);
        return (FALSE);
    }

    srv_data->service_type = service_type;
    an_strcpy(srv_data->serName, AN_DISC_SER_NAME_LEN, serName);
    an_strcpy(srv_data->regType, AN_SERVICE_TYPE_MAX_LEN, regType);
    an_strcpy(srv_data->domain, AN_DISC_DOMAIN_NAME_LEN, domain);

    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                  "\n%s Adding Srvc Srv Node to the DB "
                    "ServiceName = %s regType = %s",
                    an_srvc_event, srv_data->serName, srv_data->regType);

    an_list_enqueue_node(list, srv_data);

    return (TRUE);
}

an_srvc_srv_t *
an_srvc_add_srv_record (an_srvc_srv_ctx_t *srv_ctx)
{
    an_srvc_srv_t *srv_data = NULL;
    srv_data = an_srvc_srv_db_search(an_srvc_ptr[srv_ctx->service_type].an_srvc_srv,
                        srv_ctx->serName, srv_ctx->regType, srv_ctx->domain);
    if (NULL == srv_data) {
        srv_data = an_srvc_db_alloc_node();
        if (NULL == srv_data) {
            DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%s srvc db creation failed", an_srvc_event);
            return NULL;
        }

        an_srvc_srv_db_insert(an_srvc_ptr[srv_ctx->service_type].an_srvc_srv,
                            srv_data, srv_ctx->service_type,
                            srv_ctx->serName, srv_ctx->regType,
                            srv_ctx->domain);
        //an_srvc_ptr[srv_ctx->service_type].num_of_services++;
        srv_data->ifIndex = srv_ctx->ifIndex;
    } else {
        if (srv_data->ifIndex != srv_ctx->ifIndex) {
            DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%s service learnt on different interface", an_srvc_event);
        }

        srv_data->ifIndex = srv_ctx->ifIndex;
    }

    return srv_data;
}

boolean 
an_srvc_update_srv_record (an_srvc_srv_t *srv_data, 
            an_srvc_host_ctx_t *host_ctx, uint32_t value)
{
    an_aaa_param_t *aaa_param = NULL;
    an_config_param_t *config_param = NULL;
    an_anr_param_t *anr_param = NULL;
    uint16_t input_invalid = 0;

    if ((srv_data == NULL) || (host_ctx == NULL)) {
        return (FALSE);
    }

    input_invalid = an_srvc_validate_host(host_ctx->hostName);
    if (input_invalid) {
        return (FALSE);
    }

    an_strcpy(srv_data->hostName, AN_DISC_HOSTNAME_LEN, host_ctx->hostName);
    switch (srv_data->service_type) {
        case AN_AAA_SERVICE:
            if (value != TXT_RECORD) {
                return (TRUE);
            }

            if (srv_data->service_param == NULL) {
                srv_data->service_param = an_malloc_guard(sizeof(an_aaa_param_t),
                            "AAA data in srv db");
                if (NULL == srv_data->service_param) {
                    return (FALSE);
                }
                an_memset(srv_data->service_param, 0, sizeof(an_aaa_param_t));
            }

            aaa_param = (an_aaa_param_t *)srv_data->service_param;
            if (aaa_param->secret_key != NULL) {
                an_free_guard(aaa_param->secret_key);
                aaa_param->secret_key = NULL;
            }

            if (0 != an_strnlen(host_ctx->service_data, AN_AAA_SECRET_KEY_LENGTH)) {
                aaa_param->secret_key = an_malloc_guard(
                        an_strnlen(host_ctx->service_data, AN_AAA_SECRET_KEY_LENGTH) + 1,
                         "Secret key in srv db");
                if (NULL == aaa_param->secret_key) {
                    return (FALSE);
                }
               
                an_memset(aaa_param->secret_key, 0, an_strnlen(host_ctx->service_data,
                        AN_AAA_SECRET_KEY_LENGTH));
                an_strcpy(aaa_param->secret_key, AN_AAA_SECRET_KEY_LENGTH,
                    host_ctx->service_data);
            }

            /* The SRV record does not carry the address */
            aaa_param->auth_port = host_ctx->auth_port;
            aaa_param->acct_port = host_ctx->acct_port;
            DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, 
                    "%s SRV db update from srv record to auth_port %d acct_port %d"
            " secret key %s",
                    an_srvc_event, aaa_param->auth_port, 
                    aaa_param->acct_port, aaa_param->secret_key);
                    break;
        case AN_SYSLOG_SERVICE:
            break;
        case AN_AUTOIP_SERVICE:
            break;
        case AN_ANR_SERVICE:

            if (value != TXT_RECORD) {
                return (TRUE);
            }

            if (srv_data->service_param == NULL) {
                srv_data->service_param = an_malloc_guard(sizeof(an_anr_param_t),
                            "AAA data in srv db");
                if (NULL == srv_data->service_param) {
                    return (FALSE);
                }
                an_memset(srv_data->service_param, 0, sizeof(an_anr_param_t));
            }

            anr_param = (an_anr_param_t *)srv_data->service_param;
            if (anr_param->ca_type != NULL) {
                an_free_guard(anr_param->ca_type);
                anr_param->ca_type = NULL;
            }

            if (0 != an_strnlen(host_ctx->service_data, AN_CA_SERVER_LEN)) {
                anr_param->ca_type = an_malloc_guard(
                        an_strnlen(host_ctx->service_data, AN_CA_SERVER_LEN) + 1,
                         "CA type data in srv db");
                if (NULL == anr_param->ca_type) {
                    return (FALSE);
                }
               
                an_memset(anr_param->ca_type, 0, an_strnlen(host_ctx->service_data,
                        AN_CA_SERVER_LEN));
                an_strcpy(anr_param->ca_type, AN_CA_SERVER_LEN,
                    host_ctx->service_data);
            }

            DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, 
                    "%s SRV db update from srv record to ca type %s",
                    an_srvc_event, anr_param->ca_type);
                    break;
            break;
        case AN_CONFIG_SERVICE:
            if (value != TXT_RECORD) {
                return (TRUE);
            }
            if (srv_data->service_param == NULL) {
                srv_data->service_param = an_malloc_guard(sizeof(an_config_param_t),
                            "CONFIG data in srv db");
                if (NULL == srv_data->service_param) {
                    return (FALSE);
                }
                an_memset(srv_data->service_param, 0, sizeof(an_config_param_t));
            }

            config_param = (an_config_param_t *)srv_data->service_param;
            if (config_param->directory != NULL) {
                an_free_guard(config_param->directory);
                config_param->directory = NULL;
            }
            
            if (0 != an_strnlen(host_ctx->service_data, AN_CONFIG_PATH_LENGTH)) {
                config_param->directory = an_malloc_guard(
                        an_strlen(host_ctx->service_data), "Service data in srv db");
                if (NULL == config_param->directory) {
                    return (FALSE);
                }
    
                an_memset(config_param->directory, 0, 
                          an_strlen(host_ctx->service_data));
    
                an_strcpy(config_param->directory, AN_CONFIG_PATH_LENGTH,
                          host_ctx->service_data);
            }
            break;

        default:
            DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
                "%sInvalid service type during service resolve %d",
                an_srvc_event, srv_data->service_type);
            return (FALSE);
    }

    return (TRUE);
}

static int
an_srvc_aaaa_search_cb (void *data1, void *data2)
{
    an_srvc_aaaa_t *ctx1 = NULL;
    an_srvc_aaaa_t *ctx2 = NULL;
    int res = -1;

    if ((NULL == data1) || (NULL == data2)) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sInvalid params, AAAA data search in Srvc AAAA DB ",
                     an_srvc_event);
        return (-1);
    }

    ctx1 = (an_srvc_aaaa_t *)data1;
    ctx2 = (an_srvc_aaaa_t *)data2;

//    res = an_memcmp(&(ctx1->address), &(ctx2->address), sizeof(an_addr_t));
    res = an_addr_struct_comp(&(ctx1->address), &(ctx2->address));
    if (res==0) {
        return (0);
    }else {
        return (1);
    }
}

static int
an_srvc_host_search_cb (void *data1, void *data2)
{
    an_srvc_host_t *ctx1 = NULL;
    an_srvc_host_t *ctx2 = NULL;
    int res = -1;

    if ((NULL == data1) || (NULL == data2)) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sInvalid params, Host search in Srvc Host DB ",
                     an_srvc_event);
        return (-1);
    }

    ctx1 = (an_srvc_host_t *)data1;
    ctx2 = (an_srvc_host_t *)data2;

    res = an_strcmp(ctx1->hostName, ctx2->hostName);
    if (res==0) {
        return (0);
    }else {
        return (1);
    }
}

static int
an_srvc_srv_search_cb (void *data1, void *data2)
{
    an_srvc_srv_t *ctx1 = NULL;
    an_srvc_srv_t *ctx2 = NULL;
    int res = -1;

    if ((NULL == data1) || (NULL == data2)) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sInvalid params, srv data search in Srvc Srv DB ",
                      an_srvc_event);
        return (-1);
    }

    ctx1 = (an_srvc_srv_t *)data1;
    ctx2 = (an_srvc_srv_t *)data2;

    res = an_strcmp(ctx1->serName, ctx2->serName);
    res = res + an_strcmp(ctx1->regType, ctx2->regType);
    res = res + an_strcmp(ctx1->domain, ctx2->domain);
    if (res==0) {
        return (0);
    }else {
        return (1);
    }
}

an_srvc_aaaa_t*
an_srvc_aaaa_db_search (an_list_t *list, an_addr_t *address)
{
    an_srvc_aaaa_t goal;
    an_srvc_aaaa_t *found_data = NULL;

    if (address == NULL) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
            "\n%sInvalid parameters to search aaaa db", an_srvc_event);
        return NULL;
    }

    an_memset(&goal, 0, sizeof(an_srvc_aaaa_t));

    //an_memcpy(&goal.address, address, sizeof(an_addr_t));
    goal.address = *address;
    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                 "\n%sSearching the AAAA DB %s", an_srvc_event,
                an_addr_get_string(&goal.address));
    found_data = (an_srvc_aaaa_t *) an_list_lookup_node(list, NULL,
            (void *)&(goal), an_srvc_aaaa_search_cb);

    return (found_data);
}

an_srvc_host_t*
an_srvc_host_db_search (an_list_t *list, uint8_t *hostName)
{
    an_srvc_host_t goal = {};
    an_srvc_host_t *found_data = NULL;

    an_memset(&goal, 0, sizeof(an_srvc_host_t));

    if (an_srvc_validate_host(hostName)) {
        return NULL;
    }

    an_strcpy(goal.hostName, AN_DISC_HOSTNAME_LEN, hostName);

    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                "\nSearch the Host DB for %s", hostName);

    found_data = (an_srvc_host_t *) an_list_lookup_node(list, NULL,
                (void *)&(goal), an_srvc_host_search_cb);

    return (found_data);
}

an_srvc_srv_t*
an_srvc_srv_db_search (an_list_t *list, uint8_t *serName, uint8_t *regType,
                uint8_t *domain)
{   
    an_srvc_srv_t goal;
    an_srvc_srv_t *found_data = NULL;

    an_memset(&goal, 0, sizeof(an_srvc_srv_t));

    an_strcpy(goal.serName, AN_DISC_SER_NAME_LEN, serName);
    an_strcpy(goal.regType, AN_SERVICE_TYPE_MAX_LEN, regType);
    an_strcpy(goal.domain, AN_DISC_DOMAIN_NAME_LEN, domain);

    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                 "\nSearching the Srv DB ");

    found_data = (an_srvc_srv_t *) an_list_lookup_node(list, NULL,
            (void *)&(goal), an_srvc_srv_search_cb);

    return (found_data);
}

static an_cerrno
an_srvc_aaaa_remove_node_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_srvc_aaaa_t *aaaa_data = NULL;
    an_srvc_aaaa_t *aaaa_curr_data = NULL;
    int res = -1;
    aaaa_data = (an_srvc_aaaa_t *) context;

    if (current == NULL || list == NULL || aaaa_data == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull Input params to remove the Host ", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    aaaa_curr_data = (an_srvc_aaaa_t *) current->data;

    if (list && current) {
        res = an_memcmp(&(aaaa_data->address), &(aaaa_curr_data->address),
                        sizeof(an_addr_t));
        if (res == 0) {
            an_srvc_aaaa_node_remove (list, current, aaaa_curr_data);
        }
       //return success to continue walk
       return (AN_CERR_SUCCESS);
    }

    return (AN_CERR_V_FATAL(0, 0, EINVAL));
}

static an_cerrno
an_srvc_host_remove_node_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_srvc_host_t *host_data = NULL;
    an_srvc_host_t *host_curr_data = NULL;
    an_cerrno ret = AN_CERR_SUCCESS;
    int res = -1;

    host_data = (an_srvc_host_t *) context;

    if (current == NULL || list == NULL || host_data == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull Input params to remove the Host ", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    host_curr_data = (an_srvc_host_t *) current->data;

    if (list && current) {
        res = an_strcmp(host_data->hostName, host_curr_data->hostName);
        if (res == 0) {
            DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%s Removing Host record from Host DB",
                        an_srvc_event);
            /* free all aaaa db in this list */
            ret = an_srvc_db_walk(host_curr_data->an_aaaa_db, an_srvc_remove_and_free_all_aaaa_cb,
                              NULL);
            /* TODO Need to destroy an_aaaa_db list from host node*/
            ret = an_srvc_host_node_remove(list, current, host_curr_data);

            return (ret);
        }
       //return success to continue walk
       return (AN_CERR_SUCCESS);
    }
    return (AN_CERR_V_FATAL(0, 0, EINVAL));
}

void  an_srvc_free_srv_service_param (an_service_type_t service_type, 
                                      an_srvc_srv_t *srv_data)
{
    an_aaa_param_t *aaa_param = NULL;
    an_config_param_t *config_param = NULL;
    an_anr_param_t *anr_param = NULL;

    if ((an_srvc_validate_srvc_type(service_type)) || (NULL == srv_data)){
        return;
    }

    switch (service_type) {
        case AN_AAA_SERVICE:
            aaa_param = (an_aaa_param_t *)srv_data->service_param;
            if (NULL != aaa_param) {
                if (aaa_param->secret_key) {
                    an_free_guard(aaa_param->secret_key);
                }
                an_free_guard(aaa_param);
            }
            break;

        case AN_ANR_SERVICE:
            anr_param = (an_anr_param_t *)srv_data->service_param;
            if (NULL != anr_param) {
                if (anr_param->ca_type) {
                    an_free_guard(anr_param->ca_type);
                }
            }
            break;
        case AN_SYSLOG_SERVICE:
            break;
        case AN_CONFIG_SERVICE:
            config_param = (an_config_param_t *)srv_data->service_param;
            if (config_param != NULL) {
                if (config_param->directory) {
                    an_free_guard(config_param->directory);
                }
                an_free_guard(config_param);
            }
            break;
        case AN_AUTOIP_SERVICE:
            break;
        case AN_MAX_SERVICE:
            break;
    }
    
    return;
}

static an_cerrno
an_srvc_srv_remove_node_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    int res = -1;
    an_srvc_srv_t *srv_data = NULL;
    an_srvc_srv_t *srv_curr_data = NULL;

    srv_data = (an_srvc_srv_t *) context;

    if (current == NULL || list == NULL || srv_data == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull Input params to remove the srv ", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    srv_curr_data = (an_srvc_srv_t *) current->data;

    if (list && current) {
        res = an_strcmp(srv_data->serName, srv_curr_data->serName);
        res = res + an_strcmp(srv_data->regType, srv_curr_data->regType);
        res = res + an_strcmp(srv_data->domain, srv_curr_data->domain);
        //res = res + strcmp(srv_data->hostName, srv_curr_data->hostName); 
        if (res == 0) {
            DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%s Removing srv node from Srvc DB",
                        an_srvc_event);
            if (srv_curr_data->serviceRef) {
                an_DNSServiceRefDeallocate(srv_curr_data->serviceRef);
                srv_curr_data->serviceRef = 0;
            }

            if (!an_list_remove(list, (an_list_element_t *)current, srv_curr_data)) {
                return (AN_CERR_V_FATAL(0, 0, EINVAL));
            } else {
                DEBUG_AN_LOG(AN_LOG_ND_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%s Successfully removed Node from Srvc PTR DB",
                        an_srvc_event);
                srv_curr_data->magic_num = 0x00000000;
                an_srvc_free_srv_service_param(srv_curr_data->service_type, srv_curr_data);

                //an_srvc_ptr[srv_curr_data->service_type].num_of_services--;
                an_srvc_free_srv_node(srv_curr_data);
            } 
        }
       //return success to continue walk
       return (AN_CERR_SUCCESS);
    }
    return (AN_CERR_V_FATAL(0, 0, EINVAL));
}

void
an_srvc_srv_db_remove (an_list_t *list, an_srvc_srv_t *srv_data)
{
    an_cerrno ret;

    if (list == NULL || srv_data == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
            "Invalid inputs of srv db remove function");
        return;
    }

    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sWalking the Srvc srv DB to remove the srv db "
                 "and IP address records", an_srvc_event);

    //walk the list and delete the interface
    ret = an_srvc_db_walk(list, an_srvc_srv_remove_node_cb,
                             srv_data);

    if (an_list_is_empty(list)) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sSrvc srv DB is empty", an_srvc_event);
    }

    return;
}

void
an_srvc_aaaa_db_remove (an_list_t *list, an_srvc_aaaa_t *aaaa_data)
{
    an_cerrno ret;

    if (list == NULL || aaaa_data == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sInvalid params for aaaa db removal", an_srvc_event);
        return;
    }
       
    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sWalking the AAAA DB to remove the AAAA record "
                    , an_srvc_event);

    //walk the list and delete the interface
    ret = an_srvc_db_walk(list, an_srvc_aaaa_remove_node_cb,
                             aaaa_data);
    
    if (an_list_is_empty(list)) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAAAA DB is empty", an_srvc_event);
    }

    return;
}   
void
an_srvc_host_db_remove (an_list_t *list, an_srvc_host_t *host_data)
{
    an_cerrno ret;

    if (list == NULL || host_data == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sInvalid params for host db removal", an_srvc_event);
        return;
    }

    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sWalking the Host DB to remove the Host record "
                "and IP address records", an_srvc_event);
                 
    //walk the list and delete the interface
    ret = an_srvc_db_walk(list, an_srvc_host_remove_node_cb,
                             host_data);

    if (an_list_is_empty(list)) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sHost DB is empty", an_srvc_event);
    }

    return;
}

boolean
an_srvc_srv_db_is_empty (an_list_t *srvc_ptr_db)
{
    if (!srvc_ptr_db) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull ptr db",
                     an_srvc_event);
        return (FALSE);
    }

    if (an_list_is_empty(srvc_ptr_db)) {
       return (TRUE);
    }
        
    return (FALSE);
}

an_cerrno
an_srvc_aaaa_expire_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_srvc_aaaa_t *curr_data = NULL;
    an_cerrno ret = AN_CERR_SUCCESS;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params to AAAA DB walk", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    curr_data = (an_srvc_aaaa_t *)current->data;
    if (list && current) {
        /* for the last 120 seconds the record has not been refreshed */
        if (an_unix_time_is_elapsed(curr_data->resolved_time, 30)) {
            an_srvc_aaaa_node_remove (list, current, curr_data);
        }
    }

    return ret;
}

an_cerrno
an_srvc_host_expire_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_srvc_host_t *curr_data = NULL;
    an_cerrno ret = AN_CERR_SUCCESS;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params to Host DB walk", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    curr_data = (an_srvc_host_t *)current->data;
    if (list && current) {
        /* for the last 120 seconds the record has not been refreshed */
        if (an_unix_time_is_elapsed(curr_data->resolved_time, 30)) {
            an_srvc_aaaa_db_destroy(curr_data->an_aaaa_db);
             /* TODO Need to destroy an_aaaa_db list from host node*/
            ret = an_srvc_host_node_remove(an_srvc_host_db, current, curr_data);
        } else {
            ret = an_srvc_db_walk(curr_data->an_aaaa_db, an_srvc_aaaa_expire_cb, NULL);
        }
    }

    return ret;
}

void
an_srvc_db_expire (void)
{
    an_srvc_db_walk(an_srvc_host_db, an_srvc_host_expire_cb, NULL);
}

boolean
an_srvc_check_mem (an_srvc_srv_t *srv_data)
{
    if (NULL == srv_data) {
        return (FALSE);
    }

    if (srv_data->magic_num == 0x00ABCDEF) {
        return (TRUE);
    }

    return (FALSE);
}

uint16_t 
an_srvc_validate_servicename(uint8_t *serviceName)
{   
    uint16_t serviceNameLen = 0;
    if (NULL == serviceName) {
        return 1;
    }

    serviceNameLen = an_strnlen(serviceName, AN_DISC_SER_NAME_LEN + 1);

    if ((serviceNameLen > AN_DISC_SER_NAME_LEN) || (serviceNameLen == 0)){
        return 1;
    }

    return 0;
}

uint16_t 
an_srvc_validate_regType(uint8_t *regType)
{   
    uint16_t regTypeLen = 0;
    if (NULL == regType) {
        return 1;
    }

    regTypeLen = an_strnlen(regType, AN_SERVICE_TYPE_MAX_LEN + 1);

    if ((regTypeLen > AN_SERVICE_TYPE_MAX_LEN) || (regTypeLen == 0)) {
        return 1;
    }

    return 0;
    }

uint16_t 
an_srvc_validate_domain(uint8_t *domain)
{   
    uint16_t domainLen = 0;
    if (NULL == domain) {
        return 1;
    }

    domainLen = an_strnlen(domain, AN_DISC_DOMAIN_NAME_LEN + 1);

    if ((domainLen > AN_DISC_DOMAIN_NAME_LEN) || (domainLen == 0)) {
        return 1;
    }

    return 0;
}

uint16_t 
an_srvc_validate_host(uint8_t *hostName)
{   
    uint16_t hostNameLen = 0;
    if (NULL == hostName) {
        return 1;
    }

    hostNameLen = an_strnlen(hostName, AN_DISC_HOSTNAME_LEN);

    if ((hostNameLen > AN_DISC_HOSTNAME_LEN) || (hostNameLen == 0)) {
        return 1;
    }

    return 0;
}

uint16_t 
an_srvc_validate_srvc_type (an_service_type_t service_type)
{
    if ((service_type >= AN_AAA_SERVICE) && (service_type < AN_MAX_SERVICE)) {
        return 0;
    }
    
    return 1;
}

static an_cerrno
an_srvc_find_service_cb (an_list_t *list,
              const an_list_element_t *current, 
              an_list_element_t *next, void *context)
{
    an_srvc_srv_t *curr_data = NULL;
    an_cerrno ret = AN_CERR_SUCCESS;
    an_srvc_host_t *host_data = NULL;
    an_srvc_aaaa_t *aaaa_data = NULL;
    an_aaa_param_t *aaa_param = NULL;
    an_config_param_t *config_param = NULL;
    an_anr_param_t *anr_param = NULL;
    uint16_t *nth_element = NULL;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params to pick the "
                     "Srvc PTR DB", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }
    
    curr_data = (an_srvc_srv_t *)current->data;
    nth_element = (uint16_t *)context;

    if (list && current) {
        if (*nth_element != 0) {
            *nth_element = *nth_element - 1;
            return ret;
        }

        host_data = an_srvc_host_db_search(an_srvc_host_db, curr_data->hostName);
        if (host_data == NULL) {
            *nth_element = 0;
            return ret;
        }

        aaaa_data = an_list_get_data(an_list_get_head_elem(host_data->an_aaaa_db));
        if (aaaa_data == NULL) {
            *nth_element = 0;
            return ret;
        }
       
        switch(curr_data->service_type) {
            case AN_AAA_SERVICE:
                aaa_param = (an_aaa_param_t *)curr_data->service_param;
                if ((NULL == aaa_param) || (0 == an_strnlen (aaa_param->secret_key, 
                            AN_AAA_SECRET_KEY_LENGTH))) {
                    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                            "Not chosing service %s due to incomplete service info",
                            curr_data->hostName);
                    return ret;
                }

                aaa_sd_param_global.auth_port = aaa_param->auth_port;
                aaa_sd_param_global.acct_port = aaa_param->acct_port;
                if (aaa_sd_param_global.secret_key) {
                    an_free_guard(aaa_sd_param_global.secret_key);
                    aaa_sd_param_global.secret_key = NULL;
                }

                aaa_sd_param_global.secret_key = an_malloc_guard(
                    an_strnlen(aaa_param->secret_key, AN_AAA_SECRET_KEY_LENGTH) + 1,
                     "Global secret key placeholder");
                if (aaa_sd_param_global.secret_key != NULL) {
                    an_strcpy(aaa_sd_param_global.secret_key, AN_AAA_SECRET_KEY_LENGTH,
                        aaa_param->secret_key);
                    aaa_sd_param_global.address = aaaa_data->address;
                }

                DEBUG_AN_LOG (AN_LOG_SRVC_EVENT, AN_DEBUG_INFO,
                        "\n %sChosen address for AAA %s", 
                        an_srvc_event, an_addr_get_string(&aaa_sd_param_global.address));
                break;
            case AN_ANR_SERVICE:
                anr_param = (an_anr_param_t *)curr_data->service_param;
                if ((NULL == anr_param) || !an_is_valid_ca_type(anr_param)) {
                    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                            "Not chosing service %s due to incomplete service info",
                            curr_data->hostName);
                    return ret;
                }

                if (anr_sd_param_global.ca_type) {
                    an_free_guard(anr_sd_param_global.ca_type);
                    anr_sd_param_global.ca_type = NULL;
                }

                anr_sd_param_global.ca_type = an_malloc_guard(
                    an_strnlen(anr_param->ca_type, AN_CA_SERVER_LEN) + 1,
                     "Global ca type placeholder");
                if (anr_sd_param_global.ca_type != NULL) {
                    an_strcpy(anr_sd_param_global.ca_type, AN_CA_SERVER_LEN,
                        anr_param->ca_type);
                    anr_sd_param_global.address = aaaa_data->address;
                }

                DEBUG_AN_LOG (AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, 
                        "\n %sChosen address for ANR %s",
                        an_srvc_event, an_addr_get_string(&anr_sd_param_global.address));
               break;
            case AN_SYSLOG_SERVICE:
                syslog_sd_param_global = aaaa_data->address;
                DEBUG_AN_LOG (AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, 
                        "\n %sChosen address for Syslog %s",
                        an_srvc_event, an_addr_get_string(&syslog_sd_param_global));
                break;
            case AN_CONFIG_SERVICE:
                config_param = (an_config_param_t *)curr_data->service_param;
                if ((NULL == config_param) || (0 == an_strnlen(config_param->directory,
                                    AN_CONFIG_PATH_LENGTH))) {
                    DEBUG_AN_LOG(AN_LOG_SRVC_CONFIG, AN_DEBUG_MODERATE, NULL,
                            "\n%sNot chosing service %s due to incomplete "
                            "service info", an_srvc_config, curr_data->hostName);
                    return ret;
                }

                if (config_sd_param_global.directory) {
                    an_free_guard(config_sd_param_global.directory);
                    config_sd_param_global.directory = NULL;
                }

                config_sd_param_global.directory = an_malloc_guard(
                    an_strnlen(config_param->directory, AN_CONFIG_PATH_LENGTH),
                     "Global TFTF path placeholder");
                if (config_sd_param_global.directory != NULL) {
                    an_strcpy(config_sd_param_global.directory, AN_CONFIG_PATH_LENGTH,
                       config_param->directory);
                    config_sd_param_global.address = aaaa_data->address;
                }
                
                DEBUG_AN_LOG (AN_LOG_SRVC_CONFIG, AN_DEBUG_INFO,
                        "\n %sCONFIG Server address is %s", an_srvc_config, 
                        an_addr_get_string(&config_sd_param_global.address));
                break;

            case AN_AUTOIP_SERVICE:
                autoip_sd_param_global = aaaa_data->address;
                DEBUG_AN_LOG (AN_LOG_SRVC_EVENT, AN_DEBUG_INFO,
                        "\n%s Chosen address for Auto-IP %s",
                        an_srvc_event, 
                        an_addr_get_string(&autoip_sd_param_global));
                break;

            default:
                break;
        }       

    }
    return (AN_CERR_V_FATAL(0, 0, EINVAL));
}

void
an_srvc_get_autoip_server_address (an_addr_t *address)
{

    if (address != NULL) { 
        an_memcpy(address, &autoip_sd_param_global, sizeof (autoip_sd_param_global));
    }

    return;
}

boolean
an_srvc_find_service (an_service_type_t service_type)
{
    an_cerrno result = FALSE;
    uint16_t nth_element = 0;
    uint16_t num_of_service = 0;

    if (service_type >= AN_MAX_SERVICE) {
        return (FALSE);
    }

    if (an_list_is_empty(an_srvc_ptr[service_type].an_srvc_srv)) {
        return (FALSE);
    }

    num_of_service = an_srvc_get_num_of_service(service_type);
    if(0 == num_of_service) {
        return (FALSE);
    }

    nth_element = an_rand() % num_of_service;
    result = an_srvc_db_walk(an_srvc_ptr[service_type].an_srvc_srv,
                    an_srvc_find_service_cb, (void *)&nth_element);

    if (AN_CERR_IS_NOTOK(result)) {
        return (TRUE);
    }

    return (FALSE);
}

boolean
an_srvc_find_anr_service (an_udi_t udi, boolean firstmax)
{
    an_srvc_srv_t* srvc_link_data = NULL;
    an_list_element_t *elem = NULL;
    an_srvc_host_t *host_data = NULL;
    an_srvc_aaaa_t *aaaa_data = NULL;
    an_addr_t address = AN_ADDR_ZERO;
    an_addr_t prefered_anr_address = AN_ADDR_ZERO;
    an_addr_t max2_anr_address = AN_ADDR_ZERO;
    uint8_t anr_ip_hash[an_sha1_length];
    uint8_t max_anr_ip_hash[an_sha1_length];
    uint8_t max2_anr_ip_hash[an_sha1_length];
    boolean first_hash = FALSE;
    uint16_t hash_in_data_len = 0;
    uint16_t hash_len = 0;
    uint8_t *hash_in_data = NULL;
    int indicator = 0;
    int indicator2 = 0;
//    uint16_t i =0;
    an_v6addr_t anr_v6_address;
    if (an_list_is_empty(an_srvc_ptr[AN_ANR_SERVICE].an_srvc_srv)) {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                    "\n%sANR list is empty", an_srvc_event);
        return (FALSE);
    }
 
    AN_FOR_ALL_DATA_IN_LIST(an_srvc_ptr[AN_ANR_SERVICE].an_srvc_srv, 
                            elem, srvc_link_data) {
        if (srvc_link_data != NULL) {
            DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                    "\n%sPicked ANR service entry", an_srvc_event);

            host_data = an_srvc_host_db_search(an_srvc_host_db, 
                                               srvc_link_data->hostName);
            if (host_data == NULL) {
                continue;
            }
            aaaa_data = an_list_get_data(an_list_get_head_elem(
                                                host_data->an_aaaa_db));
            if (aaaa_data == NULL) {
                continue;
            }
            if (srvc_link_data->service_type == AN_ANR_SERVICE) {
                /*for (i = 0; i < udi.len; i++) {
                     printf("%02x", udi.data[i]);
                     if (!((i+1) % 4)) {
                         printf(" ");
                     }
                }*/
                address = aaaa_data->address;
                hash_in_data_len = sizeof(an_v6addr_t) + udi.len + 1;
                hash_in_data = (uchar *) an_malloc_guard(hash_in_data_len, 
                                        "AN hash of ANR IP and udi");
                if (hash_in_data == NULL) {
                    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                        "\n%sMemory Alloc failed for the hash of ANR IP", 
                         an_srvc_event);
                    return (FALSE);
                }
                anr_v6_address = an_addr_get_v6addr(address);
                DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                     "\n%sANR service is picked %s", an_srvc_event,
                     an_addr_get_string(&address));
                 
                an_memset(hash_in_data, 0, hash_in_data_len);
                an_memcpy(hash_in_data, &anr_v6_address, 
                          sizeof(an_v6addr_t));
                an_memcpy(hash_in_data + sizeof(an_v6addr_t), udi.data, 
                          udi.len);
                an_sign_gen_hash(hash_in_data, hash_in_data_len, 
                                               anr_ip_hash);
                hash_len = an_sha1_length;
                if (first_hash == FALSE) {
                    an_strncpy_s(max_anr_ip_hash, hash_len, anr_ip_hash, 
                                 hash_len - 1);
                    prefered_anr_address = address;                
                    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                         "\n%sFirst ANR address %s", an_srvc_event, 
                         an_addr_get_string(&prefered_anr_address));            
                    first_hash = TRUE;
                } else {
                    an_memcmp_s(max_anr_ip_hash, hash_len , anr_ip_hash, 
                                            hash_len, &indicator);
                    //indicator = 0 --> both are same
                    //indicator < 0 --> max_anr_ip_hash is lesser
                    //indicator > 0 --> max_anr_ip_hash is greater
                    if (indicator < 0) {
                        max2_anr_address = prefered_anr_address;
                        an_memcpy_s(max2_anr_ip_hash, hash_len, max_anr_ip_hash,
                                    hash_len -1);
                        prefered_anr_address = address;
                        an_strncpy_s(max_anr_ip_hash, hash_len, anr_ip_hash, 
                                     hash_len - 1);
                        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                            "\n%sUpdated ANR address %s", an_srvc_event, 
                            an_addr_get_string(&prefered_anr_address));        
                    }
                    //Present ANR IP is lesser than max_anr_IP
                    //Copy this present addr to max2_anr
                    if (an_addr_is_zero(max2_anr_address) ) {
                        max2_anr_address = address;
                        an_memcpy_s(max2_anr_ip_hash, hash_len, anr_ip_hash,
                                    hash_len -1);
                    } else if (indicator > 0){
                        //Compare present ANR IP and 2nd largest MAX ANR ip    
                        an_memcmp_s(max2_anr_ip_hash, hash_len , anr_ip_hash, 
                                           hash_len, &indicator2);
                        if (indicator2 < 0) {
                            //max2_anr_IP hash is lesser than present ANR IP
                            max2_anr_address = address;
                            an_memcpy_s(max2_anr_ip_hash, hash_len, 
                                        anr_ip_hash, hash_len -1);
                        }
                    }
                } //end of if-else ANR IP min calc
            } //end of if - ANR Service type
         }
      }
 
      if (first_hash) {
          if (firstmax) {
              anr_sd_param_global.address = prefered_anr_address;
              DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                       "\n%sSelected ANR address %s", an_srvc_event, 
                       an_addr_get_string(&prefered_anr_address));               
              return (TRUE);            
          } else {//return 2nd max
             if (!an_addr_is_zero(max2_anr_address)) { 
                 anr_sd_param_global.address = max2_anr_address;
                 DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                      "\n%sSelected 2nd ANR address %s", an_srvc_event, 
                      an_addr_get_string(&max2_anr_address));
                 return (TRUE);
             }
         } 
      }
      return (FALSE);
}



void
an_aaa_address_update (an_addr_t address, uint16_t add) 
{
    an_aaa_param_t *aaa_sd_param_local;
    boolean result;

    aaa_sd_param_local = &aaa_sd_param_global;   

    if (((add == SERVICE_ADD) && (!an_addr_struct_comp(&aaa_sd_param_local->address, &AN_ADDR_ZERO)))
        || ((add == SERVICE_REMOVE) && (!an_addr_struct_comp(&aaa_sd_param_local->address, &address)))) {
            result = an_srvc_find_service (AN_AAA_SERVICE);
            if (result == FALSE) {
                DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sAAA service is unavailable", an_srvc_event);                
            
                an_memset(aaa_sd_param_local, 0, sizeof(an_aaa_param_t));
                aaa_sd_param_local->source_if_num = an_source_if;
                an_aaa_update(aaa_sd_param_local);
            } else {
                DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sNew AAA service is chosen at %s", an_srvc_event,
                    an_addr_get_string(&aaa_sd_param_local->address));
                aaa_sd_param_local->source_if_num = an_source_if;
                an_aaa_update(aaa_sd_param_local);
            }
    }
}

void
an_syslog_address_update (an_addr_t address, uint16_t value)
{
    boolean result = FALSE;
    if (((value == SERVICE_ADD) && (!an_addr_struct_comp(&syslog_sd_param_global, &AN_ADDR_ZERO))) 
        || ((value == SERVICE_REMOVE) && (!an_addr_struct_comp(&syslog_sd_param_global, &address)))) {
            result = an_srvc_find_service (AN_SYSLOG_SERVICE);
            if (result == FALSE) {
                DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n%sSyslog service is unavailable", an_srvc_event);
                syslog_sd_param_global = AN_ADDR_ZERO;
                an_syslog_set_server_address(&syslog_sd_param_global, FALSE);
            } else {
                DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sNew Syslog service is at %s", an_srvc_event,
                     an_addr_get_string(&syslog_sd_param_global));
                an_syslog_set_server_address(&syslog_sd_param_global, TRUE);
            }
    }
}

void
an_anr_address_update (an_addr_t address, uint16_t value)
{
    boolean result = FALSE;
    int32_t cmp_res = 0;
    an_anr_param_t *anr_sd_param_local = NULL;
    an_cert_api_ret_enum cert_result;
    an_addr_t anr_ip = AN_ADDR_ZERO;
    boolean ra_mode_server = FALSE;

    if (an_anra_is_live()) {
        return;
    }

    anr_sd_param_local = &anr_sd_param_global;
    if ((value == SERVICE_ADD) &&  (!an_addr_struct_comp(&anr_sd_param_global.address, &AN_ADDR_ZERO))) {
        result = an_srvc_find_service (AN_ANR_SERVICE);
        if (result == FALSE) {
           DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
                    "\n %s ANR service is unavailable", an_srvc_event);
            an_memset(anr_sd_param_local, 0, sizeof(an_anr_param_t));
        } else {
           DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                    "%s New ANR service is at %s",an_srvc_event,
           an_addr_get_string(&anr_sd_param_global.address));
           an_set_anra_ip(anr_sd_param_global.address);
           
           if (an_tp_exists(AN_DOMAIN_TP_LABEL)) {
                cmp_res = an_strcmp(anr_sd_param_global.ca_type, 
                            an_anra_get_ca_type_id_to_str(ANR_LOCAL_CA));
                ra_mode_server = (!cmp_res) ? (FALSE) : (TRUE);
                cert_result = an_cert_update_trustpoint(anr_sd_param_global.address, ra_mode_server);
           } else {
              cert_result = AN_CERT_CRYPTO_GET_TP_FROM_LABEL_INVALID;
           }
           if (cert_result != AN_CERT_API_SUCCESS) {
              DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sReenrollment trustpoint not updated",
                        an_bs_event);
            } else {
                an_set_anr_ip_for_cert_renewal(anr_sd_param_global.address);
           }

            /* remove ntp peer with nbr and start with RA */
            an_acp_start_ntp_with_ra (anr_sd_param_global.address);
         }
    } else if (value == SERVICE_REMOVE) {
         if (!an_addr_struct_comp(&anr_sd_param_global.address, &address)) {
             result = an_srvc_find_service (AN_ANR_SERVICE);
             if (result == FALSE) {
                 DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
                     "\n %s ANR service is unavailable", an_srvc_event);
                an_memset(&anr_sd_param_global, 0, sizeof(an_anr_param_t));
                /* remove ntp peer with RA and start with peers */
                an_acp_start_ntp_with_nbrs();
             } else {
                 DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "%s New ANR service is at %s",an_srvc_event,
                 an_addr_get_string(&anr_sd_param_global.address));
                 an_set_anra_ip(anr_sd_param_global.address);
                 cmp_res = an_strcmp(anr_sd_param_global.ca_type,
                            an_anra_get_ca_type_id_to_str(ANR_LOCAL_CA));
                 ra_mode_server = (!cmp_res) ? (FALSE) : (TRUE);
                an_acp_enable_clock_sync_with_ra(anr_sd_param_global.address);
             }
         }

         anr_ip = an_get_anr_ip_for_cert_renewal();
         if (!an_addr_struct_comp(&anr_ip, &address)) {
             if (an_tp_exists(AN_DOMAIN_TP_LABEL)) {
                cert_result = an_cert_update_trustpoint(anr_sd_param_global.address, ra_mode_server);
             } else {
                 cert_result = AN_CERT_CRYPTO_GET_TP_FROM_LABEL_INVALID;
             }

             if (cert_result != AN_CERT_API_SUCCESS) {
                 DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                      "\n%sReenrollment trustpoint not updated",
                     an_bs_event);
            } else {
                an_set_anr_ip_for_cert_renewal(anr_sd_param_global.address);
             }
         }
    }
}

void
an_config_address_update (an_addr_t address, uint16_t value)
{
    an_config_param_t *config_sd_param_local;
    boolean result;

    config_sd_param_local = &config_sd_param_global;   

    if (((value == SERVICE_ADD) && (!an_addr_struct_comp(&config_sd_param_local->address, &AN_ADDR_ZERO)))
        || ((value == SERVICE_REMOVE) && (!an_addr_struct_comp(&config_sd_param_local->address, &address)))) {
            result = an_srvc_find_service(AN_CONFIG_SERVICE);
            if (result == FALSE) {
                DEBUG_AN_LOG(AN_LOG_SRVC_CONFIG, AN_DEBUG_SEVERE, NULL,
                    "\n%sCONFIG service is unavailable", an_srvc_config);

                an_memset(config_sd_param_local, 0, sizeof(an_config_param_t));
            } else {
                DEBUG_AN_LOG(AN_LOG_SRVC_CONFIG, AN_DEBUG_INFO, NULL,
                    "\n%sNew CONFIG service is chosen at %s", an_srvc_config,
                    an_addr_get_string(&config_sd_param_local->address));
            }
    }
}


void
an_autoip_address_update (an_addr_t address, uint16_t value)
{
    boolean result;


    if (((value == SERVICE_ADD) && 
        (!an_addr_struct_comp(&autoip_sd_param_global, &AN_ADDR_ZERO)))
        || ((value == SERVICE_REMOVE) && 
        (!an_addr_struct_comp(&autoip_sd_param_global, &address)))) {
            result = an_srvc_find_service(AN_AUTOIP_SERVICE);
            if (result == FALSE) {
                DEBUG_AN_LOG(AN_LOG_SRVC_CONFIG, AN_DEBUG_SEVERE, NULL,
                    "\n%s Auto-IP serive is unavailable", an_srvc_config);
                autoip_sd_param_global = AN_ADDR_ZERO;
            } else {
                DEBUG_AN_LOG(AN_LOG_SRVC_CONFIG, AN_DEBUG_INFO, NULL,
                    "\n%s Auto-IP service is chosen at %s", an_srvc_config,
                    an_addr_get_string(&autoip_sd_param_global));
            }
    }
}


void
an_srvc_notify_service_withdraw (an_service_type_t service_type, 
                an_srvc_aaaa_t *aaaa_data) 
{
    switch (service_type) {
        case AN_AAA_SERVICE:
            an_aaa_address_update(aaaa_data->address, 0);
            break;
        case AN_SYSLOG_SERVICE:
            an_syslog_address_update(aaaa_data->address, 0);
            break;
        case AN_ANR_SERVICE:
            an_anr_address_update(aaaa_data->address, 0);
            break;
        case AN_CONFIG_SERVICE:
            an_config_address_update(aaaa_data->address, 0);
            break;
        case AN_AUTOIP_SERVICE:
            an_autoip_address_update(aaaa_data->address, 0);
            break;
        default:
            break;
    }
}

an_cerrno
an_srvc_notify_service_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_srvc_aaaa_t *curr_data = NULL;
    an_service_type_t service_type;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params to remove link in the "
                     "Srvc AAAA DB", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    curr_data = (an_srvc_aaaa_t *)current->data;
    service_type = *(an_service_type_t *)context;
    if (list && current) {
        an_srvc_notify_service_withdraw(service_type, curr_data);
        return (AN_CERR_SUCCESS);
    }

    return (AN_CERR_V_FATAL(0, 0, EINVAL));;
}

void
an_srvc_notify_address_change (an_addr_t address, uint16_t add) 
{
    uint16_t i = 0;
    for (i = 0; i < AN_MAX_SERVICE; i++) {
        switch (i) {
            case AN_AAA_SERVICE:
                an_aaa_address_update(address, add);
                break;
            case AN_SYSLOG_SERVICE:
                an_syslog_address_update(address, add);
                break;
            case AN_ANR_SERVICE:
                an_anr_address_update(address, add);
                break;
            case AN_CONFIG_SERVICE:
                an_config_address_update(address, add);
                break;
            case AN_AUTOIP_SERVICE:
                an_autoip_address_update(address, add);
                break;
            default:
                break;
        }
    }
}

void
an_srvc_db_init (void)
{
    uint16_t i = 0;
    an_srvc_srv_ctx_pool = NULL;
    an_srvc_host_ctx_pool = NULL;
    an_srvc_aaaa_ctx_pool = NULL;

    for (i = 0; i < AN_MAX_SERVICE; i++) {
        an_srvc_ptr[i].an_srvc_srv = NULL;
        an_srvc_ptr[i].num_of_services = 0;
        an_srvc_db_create(&an_srvc_ptr[i].an_srvc_srv);
    }
    an_srvc_host_db = NULL;
    (void)an_srvc_db_create(&an_srvc_host_db);

    /* Set mdns packet processing rate per second */
    an_mdns_io_set_rate_limit_rate(50); 

}

void
an_srvc_db_uninit (void)
{
    uint16_t i = 0;
    an_srvc_host_db_destroy(an_srvc_host_db);
    for (i = 0; i < AN_MAX_SERVICE; i++) {
        an_srvc_srv_db_destroy(an_srvc_ptr[i].an_srvc_srv);
        an_srvc_ptr[i].num_of_services = 0;
        an_srvc_ptr[i].an_srvc_srv = NULL;
    }
    an_srvc_host_db = NULL;
}

void
an_service_stop (void)
{   
    an_aaa_param_t *aaa_sd_param_local;
    
    aaa_sd_param_local = &aaa_sd_param_global;

    an_aaa_disable(aaa_sd_param_local);
}   
    

void
an_service_start (void)
{ 
    an_sd_cfg_if_commands(an_source_if, TRUE);
 
#if 0 
    an_aaa_param_t *aaa_sd_param_local;
    
    aaa_sd_param_local = &aaa_sd_param_global;
    aaa_sd_param_local->source_if_num = an_source_if;
    an_aaa_enable(aaa_sd_param_local);
#endif
}

#if 0
uint16_t
an_srvc_get_num_of_service (an_service_type_t service_type)
{
    uint16_t input_invalid = 0;

    input_invalid = an_srvc_validate_srvc_type (service_type);
    if (input_invalid) {
        return 0;
    }

    return(an_srvc_ptr[service_type].num_of_services);
}
#endif

static an_cerrno
an_srvc_count_num_of_valid_srvc_instance_cb(an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_srvc_srv_t *curr_data = NULL;
    an_service_type_t service_type = AN_MAX_SERVICE;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params to remove link in the "
                     "Srvc PTR DB", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    curr_data = (an_srvc_srv_t *)current->data;
    if (list && current) {
        if (curr_data->host_ptr != NULL) {
            if (!an_list_is_empty(curr_data->host_ptr->an_aaaa_db)) {
                service_type = *((an_service_type_t *)context);
                if (!an_srvc_validate_srvc_type(service_type)) {
                    an_srvc_ptr[service_type].num_of_services++;
                }
            }
        }

    }
    
    return (AN_CERR_SUCCESS);
}
 
uint16_t
an_srvc_get_num_of_service (an_service_type_t service_type)
{
    an_cerrno ret;
    uint16_t input_invalid = 0;

    input_invalid += an_srvc_validate_srvc_type(service_type);
    
    if (input_invalid) {
        return (0);
    }    
   
    an_srvc_ptr[service_type].num_of_services = 0; 
    ret = an_srvc_db_walk(an_srvc_ptr[service_type].an_srvc_srv, 
                        an_srvc_count_num_of_valid_srvc_instance_cb,
                              (uint16_t *)&service_type);

    return an_srvc_ptr[service_type].num_of_services;
}

static an_cerrno
an_srvc_unlink_srvc_instance_from_host_cb(an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_srvc_srv_t *curr_data = NULL;
    an_srvc_host_t *host_data = NULL;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params when unlinking srvc instance "
                     "from host DB", an_srvc_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    host_data = (an_srvc_host_t *)context;
    curr_data = (an_srvc_srv_t *)current->data;
    if (list && current && host_data) {
        if (curr_data->host_ptr != NULL) {
            if (curr_data->host_ptr == host_data) {
                curr_data->host_ptr = NULL;
            }
        }
    }
    
    return (AN_CERR_SUCCESS);
}

void
an_srvc_unlink_srvc_instance_from_host_db (an_srvc_host_t *host_data) 
{
    an_service_type_t service_type = 0;
   
    for (service_type = 0; service_type < AN_MAX_SERVICE; service_type++) {
        an_srvc_db_walk(an_srvc_ptr[service_type].an_srvc_srv,
                        an_srvc_unlink_srvc_instance_from_host_cb,
                              host_data);
    }

    return;
}


