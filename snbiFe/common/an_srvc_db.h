/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_SRVC_DB_H__
#define __AN_SRVC_DB_H__

#include "../al/an_types.h"
#include "../al/an_avl.h"
#include "../al/an_list.h"
#include "an.h"

#define AN_DISC_HOSTNAME_LEN 64
#define AN_DISC_SER_NAME_LEN 64
#define AN_DISC_DOMAIN_NAME_LEN 64
#define AN_SERVICE_TYPE_MAX_LEN 64

#define AN_DISC_RRDATA_LEN (AN_SERVICE_TYPE_MAX_LEN + AN_DISC_SER_NAME_LEN + AN_DISC_DOMAIN_NAME_LEN)

#define SERVICE_ADD  1
#define SERVICE_REMOVE 0

#define SRV_RECORD 0
#define TXT_RECORD 1
#define AN_TXT_REC_LENGTH  255

an_mem_chunkpool_t *an_srvc_srv_ctx_pool;
an_mem_chunkpool_t *an_srvc_host_ctx_pool;
an_mem_chunkpool_t *an_srvc_aaaa_ctx_pool;

an_aaa_param_t aaa_sd_param_global;
an_addr_t syslog_sd_param_global;
an_anr_param_t anr_sd_param_global;
an_config_param_t config_sd_param_global;
extern an_addr_t autoip_sd_param_global;

typedef enum an_service_type_t_ {

    AN_AAA_SERVICE,
    AN_SYSLOG_SERVICE,
    AN_ANR_SERVICE,
    AN_CONFIG_SERVICE,
    AN_AUTOIP_SERVICE,
    AN_MAX_SERVICE,

} an_service_type_t;

typedef struct an_ctx_info_t_ {
    an_service_type_t an_service_type;
} an_ctx_info_t;

an_ctx_info_t an_ctx_info[AN_MAX_SERVICE];

typedef struct an_srvc_srv_ctx_t_ {
    an_service_type_t service_type;
    uint8_t serName[AN_DISC_SER_NAME_LEN];
    uint8_t regType[AN_SERVICE_TYPE_MAX_LEN];
    uint8_t domain[AN_DISC_DOMAIN_NAME_LEN];
    an_if_t ifIndex;
} an_srvc_srv_ctx_t;

typedef struct an_srvc_host_ctx_t_ {
    an_service_type_t service_type;
    uint8_t serName[AN_DISC_SER_NAME_LEN];
    uint8_t regType[AN_SERVICE_TYPE_MAX_LEN];
    uint8_t domain[AN_DISC_DOMAIN_NAME_LEN];
    uint8_t hostName[AN_DISC_HOSTNAME_LEN];
    an_if_t ifIndex;
    uint32_t auth_port;
    uint32_t acct_port;
    uint8_t service_data[AN_TXT_REC_LENGTH];
} an_srvc_host_ctx_t;
    
typedef struct an_srvc_aaaa_ctx_t_ {
    uint8_t hostName[AN_DISC_HOSTNAME_LEN];
    an_addr_t address;
} an_srvc_aaaa_ctx_t;

typedef struct an_srvc_aaaa_t_ {
    an_addr_t address;
    an_unix_time_t resolved_time;
} an_srvc_aaaa_t;

typedef struct an_srvc_host_t_ {
    an_DNSServiceRef serviceRef;
    uint8_t hostName[AN_DISC_HOSTNAME_LEN];
    an_unix_time_t resolved_time;
    an_list_t *an_aaaa_db;
} an_srvc_host_t;

typedef struct an_srvc_srv_t_ {
    uint32_t magic_num;
    an_service_type_t service_type;
    an_DNSServiceRef serviceRef;
    uint8_t serName[AN_DISC_SER_NAME_LEN];
    uint8_t regType[AN_SERVICE_TYPE_MAX_LEN];
    uint8_t domain[AN_DISC_DOMAIN_NAME_LEN];
    uint8_t hostName[AN_DISC_HOSTNAME_LEN];
    an_srvc_host_t *host_ptr;
    an_if_t ifIndex;
    void *service_param;
} an_srvc_srv_t;

typedef struct an_srvc_ptr_db_ {
    an_list_t *an_srvc_srv;
    uint16_t num_of_services;
} an_srvc_ptr_db;

an_srvc_ptr_db an_srvc_ptr[AN_MAX_SERVICE];

an_list_t *an_srvc_host_db;

void an_show_srvc_db(an_service_type_t service_type);

an_srvc_srv_t* an_srvc_srv_db_search(an_list_t *list, uint8_t *serName, uint8_t *regType,
                uint8_t *domain);
boolean an_srvc_check_mem(an_srvc_srv_t *srv_data);
uint16_t an_srvc_validate_servicename(uint8_t *serviceName);
uint16_t an_srvc_validate_regType(uint8_t *regType);
uint16_t an_srvc_validate_domain(uint8_t *domain);
uint16_t an_srvc_validate_host(uint8_t *hostName);
uint16_t an_srvc_validate_srvc_type(an_service_type_t service_type);
an_srvc_srv_t *an_srvc_add_srv_record(an_srvc_srv_ctx_t *srv_ctx);
boolean an_srvc_update_srv_record(an_srvc_srv_t *srv_data, an_srvc_host_ctx_t *host_ctx,
                    uint32_t value);
boolean an_srvc_aaaa_db_insert(an_list_t *list, an_srvc_aaaa_t *aaaa_data,
                    an_addr_t *address);
boolean an_srvc_host_db_insert(an_list_t *list, an_srvc_host_t *host_data,
        uint8_t *hostName);
an_srvc_aaaa_t* an_srvc_aaaa_db_search(an_list_t *list, an_addr_t *address);
an_srvc_host_t* an_srvc_host_db_search(an_list_t *list, uint8_t *hostName);

void an_srvc_aaaa_db_remove(an_list_t *list, an_srvc_aaaa_t *aaaa_data);
void an_srvc_host_db_remove(an_list_t *list, an_srvc_host_t *host_data);

an_cerrno an_srvc_srv_db_destroy(an_list_t *list);
an_cerrno an_srvc_host_db_destroy(an_list_t *list);
an_cerrno an_srvc_aaaa_db_destroy(an_list_t *list);
boolean an_srvc_db_create(an_list_t **ptr_data);
an_srvc_aaaa_t *an_srvc_aaaa_alloc_node(void);
an_srvc_host_t *an_srvc_host_alloc_node(void);
an_srvc_srv_t * an_srvc_db_alloc_node(void);
void an_srvc_srv_db_remove(an_list_t *list, an_srvc_srv_t *srv_data);
an_cerrno an_srvc_db_walk(an_list_t *list, an_list_walk_handler callback_func,
                     void *srv_data);
an_cerrno an_srvc_notify_service_cb(an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context);
void an_srvc_notify_address_change(an_addr_t address, uint16_t add);
void an_DNSServiceRefDeallocate(an_DNSServiceRef serviceRef);
void an_srvc_db_init(void);
void an_srvc_db_uninit(void);
void an_srvc_db_expire(void);
void an_service_start(void);
void an_service_stop(void);
void an_discover_services(an_if_t ifhndl);
void an_discover_services_stop(an_if_t ifhndl);
boolean an_srvc_find_service(an_service_type_t service_type);
boolean an_srvc_find_anr_service(an_udi_t udi, boolean firstmax);
uint16_t an_srvc_get_num_of_service(an_service_type_t service_type);
void an_srvc_unlink_srvc_instance_from_host_db(an_srvc_host_t *host_data);
void an_srvc_get_autoip_server_address(an_addr_t *address);
#endif

