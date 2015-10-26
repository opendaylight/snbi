/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#ifndef __AN_EVENT_DB_H__
#define __AN_EVENT_DB_H__
#include "../al/an_list.h"
#include "../al/an_logger.h"
#include "../al/an_types.h"
#include "../al/an_mem.h"
#include "an_nbr_db.h"

typedef void (*fn_handler)(void *);

typedef enum an_event_e_ {
    AN_EVENT_INVALID,
    AN_EVENT_UDI_AVAILABLE,
    AN_EVENT_SUDI_AVAILABLE,
    AN_EVENT_SYSTEM_CONFIGURED,
    AN_EVENT_INTERFACE_UP,
    AN_EVENT_INTERFACE_DOWN,
    AN_EVENT_INTERFACE_ACTIVATE,
    AN_EVENT_INTERFACE_DEACTIVATE,
    AN_EVENT_INTERFACE_ERASED,
    AN_EVENT_INTF_AUTONOMIC_ENABLE,
    AN_EVENT_INTF_AUTONOMIC_DISABLE,
    AN_EVENT_ANR_UNINIT,
    AN_EVENT_ANR_LIVE_PENDING,
    AN_EVENT_ANR_SHUT_PENDING,
    AN_EVENT_ANR_DELETE_PENDING,
    AN_EVENT_ANR_UP_LOCALLY,
    AN_EVENT_ANR_SHUT,
    AN_EVENT_ANR_REACHABLE,
    AN_EVENT_DEVICE_BOOTSTRAP,
    AN_EVENT_SD_SRVC_RECEIVED,
    AN_EVENT_SD_SRVC_RESOLVED,
    AN_EVENT_SD_HOST_RESOLVED,
    AN_EVENT_ACP_INIT,
    AN_EVENT_ACP_PRE_UNINIT,
    AN_EVENT_ACP_UNINIT,
    AN_EVENT_ACP_ON_LINK_CREATED,
    AN_EVENT_ACP_ON_LINK_REMOVED,
    AN_EVENT_TIMER_NI_CERT_REQUEST_EXPIRED,
    AN_EVENT_TIMER_HELLO_REFRESH_EXPIRED,
    AN_EVENT_TIMER_ANR_BS_RETRY_EXPIRED,
    AN_EVENT_TIMER_CERT_REVOKE_CHECK_EXPIRED,
    AN_EVENT_TIMER_NBR_CERT_REVALIDATE_EXPIRED,
    AN_EVENT_TIMER_NBR_CERT_RENEW_EXPIRED,
    AN_EVENT_TIMER_MY_CERT_RENEW_EXPIRED,
    AN_EVENT_TIMER_GENERIC_EXPIRED,
    AN_EVENT_TIMER_NBR_LINK_CLEANUP_EXPIRED,
    AN_EVENT_NBR_LINK_ADD,
    AN_EVENT_NBR_ADD,
    AN_EVENT_NBR_REFRESHED,
    AN_EVENT_NBR_PARAMS_CAHNGED,
    AN_EVENT_NBR_INSIDE_DOMAIN,
    AN_EVENT_NBR_OUTSIDE_DOMAIN,
    AN_EVENT_NBR_CERT_VALIDITY_EXPIRED,
    AN_EVENT_DOMAIN_DEVICE_CERT_EXPIRED,
    AN_EVENT_DOMAIN_DEVICE_CERT_RENEWED,
    AN_EVENT_VALIDATION_CERT_RESPONSE,
    AN_EVENT_CLOCK_SYNCHRONISED,
    AN_EVENT_DEVICE_CERT_ENROLL_SUCCESS,
    AN_EVENT_DEVICE_CERT_ENROLL_FAILED,
    AN_EVENT_TIMER_EXTERNAL_ANR_BS_RETRY_EXPIRED,
    AN_EVENT_MAX,
}an_event_e;

typedef enum an_modules_e_ {
    AN_MODULE_INVALID,
    AN_MODULE_CD,
    AN_MODULE_ND,
    AN_MODULE_SERVICE_DISCOVERY,
    AN_MODULE_BS,
    AN_MODULE_ACP,
    AN_MODULE_IDP,
    AN_MODULE_REGISTRAR,
    AN_MODULE_INTENT,
    AN_MODULE_CONFIG_DOWNLOAD,
    AN_MODULE_INTF_MGR,
    AN_MODULE_GENERIC,
    AN_MODULE_EXTERNAL_ANRA,
    AN_MODULE_MAX,
} an_modules_e;

typedef struct an_event_ {
    an_event_e event_type;
    an_list_t *an_event_consumer_db;
} an_event_t;

an_event_t an_event_consumer_ptr[AN_EVENT_MAX];

typedef struct an_event_consumer_t_ {
    an_modules_e consumer;
    fn_handler handler;
} an_event_consumer_t;

void an_event_add_event_to_db(an_event_e an_event);
void an_event_remove_event_from_db(an_event_e an_event);
void an_event_register_consumer(an_modules_e module,
                        an_event_e an_event, fn_handler handler);
void an_event_unregister_consumer_eventhandler(an_modules_e module, 
                        an_event_e an_event);

void an_event_db_init(void);
void an_event_db_uninit(void);
void an_event_show_event_db(void);
void an_event_notify_consumers(an_event_e an_event, void *context);

typedef struct an_event_service_discovery_info_t_ {
    void *context;
    int value;
} an_event_service_discovery_info_t;

typedef struct an_event_nbr_link_add_lost_info_t_ {
    an_nbr_t *nbr;
    an_nbr_link_spec_t *nbr_link_data;
} an_event_nbr_link_add_lost_info_t;

typedef struct an_event_validation_cert_response_info_t_ {
    an_cert_validation_result_e status;
    void *device_ctx;
}an_event_validation_cert_response_info_t;

typedef struct an_event_cert_enroll_info_t_ {
    uchar *cert_der;
    uint16_t cert_len;
    an_udi_t dest_udi;
    an_addr_t proxy_device;
    an_iptable_t iptable;
} an_event_cert_enroll_info_t;

#endif
