/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_LOGGER_H__
#define __AN_LOGGER_H__

#include "an_types.h"
#include "an_tunnel.h"

#define MAX_AN_SYSLOG_MSG_TYPE 100

extern const uint8_t * an_timer_prefix;
extern const uint8_t * an_nd_prefix;
extern const uint8_t * an_cd_prefix;
extern const uint8_t * an_tlv_prefix;
extern const uint8_t * an_srvc_prefix;
extern const uint8_t * an_msg_mgr_prefix;
extern const uint8_t * an_nbr_link_prefix;
extern const uint8_t * an_topo_prefix;
extern const uint8_t * an_pak_prefix;
extern const uint8_t * an_ni_prefix;
extern const uint8_t * an_nd_event;
extern const uint8_t * an_nd_pak;
extern const uint8_t * an_nd_db;
extern const uint8_t * an_bs_event;
extern const uint8_t * an_bs_pak;
extern const uint8_t * an_bs_acp;
extern const uint8_t * an_ra_event;
extern const uint8_t * an_ra_db;
extern const uint8_t * an_srvc_event;
extern const uint8_t * an_srvc_pak;
extern const uint8_t * an_srvc_aaa;
extern const uint8_t * an_srvc_ntp;
extern const uint8_t * an_srvc_syslog;
extern const uint8_t * an_srvc_idp;

typedef enum an_debug_level_e_ {
    AN_DEBUG_INFO,
    AN_DEBUG_MODERATE,
    AN_DEBUG_SEVERE,
    AN_DEBUG_MAX,
} an_debug_level_e;

typedef struct an_debug_context_ {
    uint8_t *if_name;
    an_udi_t udi;
} an_debug_context_t;

typedef enum an_log_cfg_e_ {
    AN_LOG_CFG_NONE         =   0,

    AN_LOG_CFG_ND,
    AN_LOG_CFG_CD,
    AN_LOG_CFG_NI,
    AN_LOG_CFG_BS,
    AN_LOG_CFG_ACP,
    AN_LOG_CFG_MESSAGE,
    AN_LOG_CFG_ANRA,
    AN_LOG_CFG_EVENT,
    AN_LOG_CFG_SUDI,
    AN_LOG_CFG_TLV,
    AN_LOG_CFG_MSG_MGR,
    AN_LOG_CFG_IDP,
    AN_LOG_CFG_IF,
    AN_LOG_CFG_ERR,
    AN_LOG_CFG_DB,
    AN_LOG_CFG_IP,
    AN_LOG_CFG_PAK,
    AN_LOG_CFG_TIMER,
    AN_LOG_CFG_AVL,
    AN_LOG_CFG_SIGN,
    AN_LOG_CFG_CERT,
    AN_LOG_CFG_CLI,
    AN_LOG_CFG_MASA,
    AN_LOG_CFG_MEM,
    AN_LOG_CFG_SRVC,
    AN_LOG_CFG_TOPO,
    AN_LOG_CFG_AAA,    
    AN_LOG_CFG_LIST,    
    AN_LOG_CFG_NBR_LINK,
    AN_LOG_CFG_CNP,
    AN_LOG_CFG_NTP,
    AN_LOG_CFG_FILE,
    AN_LOG_CFG_ALL,
} an_log_cfg_e;

typedef uint64_t an_log_type;

an_log_type AN_LOG_NONE;
an_log_type AN_LOG_ND;
an_log_type AN_LOG_CD;
an_log_type AN_LOG_NI;
an_log_type AN_LOG_BS;
an_log_type AN_LOG_ACP;
an_log_type AN_LOG_MESSAGE;
an_log_type AN_LOG_ANRA;
an_log_type AN_LOG_EVENT;
an_log_type AN_LOG_SUDI;
an_log_type AN_LOG_TLV;
an_log_type AN_LOG_MSG_MGR;
an_log_type AN_LOG_IDP;
an_log_type AN_LOG_IF;
an_log_type AN_LOG_ERR;
an_log_type AN_LOG_DB;
an_log_type AN_LOG_IP;
an_log_type AN_LOG_PAK;
an_log_type AN_LOG_TIMER;
an_log_type AN_LOG_AVL;
an_log_type AN_LOG_SIGN;
an_log_type AN_LOG_CERT;
an_log_type AN_LOG_CLI;
an_log_type AN_LOG_MASA;
an_log_type AN_LOG_MEM;
an_log_type AN_LOG_SRVC;
an_log_type AN_LOG_TOPO;
an_log_type AN_LOG_AAA;
an_log_type AN_LOG_LIST;
an_log_type AN_LOG_CNP;
an_log_type AN_LOG_NBR_LINK;
an_log_type AN_LOG_NTP;
an_log_type AN_LOG_FILE;
an_log_type AN_LOG_ALL;

typedef enum an_log_type_e_ {
    AN_LOG_NONCE,
    AN_LOG_ND_EVENT,
    AN_LOG_ND_PACKET,
    AN_LOG_ND_DB,
    AN_LOG_ND_ALL,

    AN_LOG_BS_EVENT,
    AN_LOG_BS_PACKET,
    AN_LOG_BS_ALL,

    AN_LOG_RA_EVENT,
    AN_LOG_RA_DB,
    AN_LOG_RA_ALL,

    AN_LOG_SRVC_EVENT,
    AN_LOG_SRVC_PACKET,
    AN_LOG_SRVC_AAA,
    AN_LOG_SRVC_NTP,
    AN_LOG_SRVC_SYSLOG,
    AN_LOG_SRVC_IDP,
    AN_LOG_SRVC_ALL,

    AN_LOG_ALL_ALL,

} an_log_type_e;

typedef enum an_syslog_msg_e_ {
    AN_SYSLOG_DEVICE_ALLOWED = 1,

    AN_SYSLOG_DEVICE_NOT_ALLOWED,
    AN_SYSLOG_DEVICE_BOOTSTRAPPED,
    AN_SYSLOG_MASA_AUTH_FAIL,
    AN_SYSLOG_MASA_AUDIT_LOG_FAIL,
    AN_SYSLOG_MASA_NOT_CONFIG,
    AN_SYSLOG_ANRA_UP,
    AN_SYSLOG_ANRA_DOWN,
    AN_SYSLOG_ANRA_WHITELIST_CONFIG,
    AN_SYSLOG_ANRA_WHITELIST_NOT_CONFIG,
    AN_SYSLOG_ANRA_WHITELIST_FILE_ERROR,
    AN_SYSLOG_IDP_INTENT_FILE_ERROR,
    AN_SYSLOG_IDP_INTENT_VER_UPDATED,
    AN_SYSLOG_IDP_INTENT_VER_OLD_DISCARD,
    AN_SYSLOG_SERVICE_LEARNT,
    AN_SYSLOG_UDI_AVAILABLE,
    AN_SYSLOG_SUDI_AVAILABLE,
    AN_SYSLOG_NBR_IN_DOMAIN,
    AN_SYSLOG_NBR_OUT_DOMAIN,
    AN_SYSLOG_NBR_ADDED,
    AN_SYSLOG_NBR_LOST,
    AN_SYSLOG_NBR_DOMAIN_CERT_VALID,
    AN_SYSLOG_NBR_DOMAIN_CERT_INVALID,
    AN_SYSLOG_DOMAIN_KEY_GEN_FAIL,
    AN_SYSLOG_ANRA_SIGN_VERIFY_FAIL,
    AN_SYSLOG_MASA_AUTH_TOKEN_PARSE_ERROR,
    AN_SYSLOG_TLV_PARSE_ALIGN_ERROR,
    AN_SYSLOG_TLV_PARSE_LEN_INCORRECT,
    AN_SYSLOG_MSG_INVALID_HEADER,
    
    AN_SYSLOG_ACP_ROUTING_GLOBAL_ENABLED,
    AN_SYSLOG_ACP_ROUTING_INTERFACE_ENABLED,
    AN_SYSLOG_ACP_ROUTING_GLOBAL_DISABLE, 
    
    AN_SYSLOG_ACP_CHANNEL_TO_NBR_CREATED,
    AN_SYSLOG_ACP_CHANNEL_TO_NBR_FAILED,
    AN_SYSLOG_ACP_CHANNEL_TO_NBR_REMOVED,

    AN_SYSLOG_ACP_IPSEC_TO_NBR_CREATED,
    AN_SYSLOG_ACP_IPSEC_TO_NBR_FAILED,
    AN_SYSLOG_ACP_IPSEC_TO_NBR_REMOVED,
} an_syslog_msg_e;

void an_debug_log(an_log_type_e type, an_debug_level_e lev, 
                  void *context, const char *fmt, ...);
#define DEBUG_AN_LOG(type, lev, context, X, ...) \
        an_debug_log(type, lev, context, X, ##__VA_ARGS__);

void an_log_init(void);
void an_log_uninit(void);
boolean an_log_is_enabled_for_type_lev(an_log_type_e type, an_debug_level_e lev);
void an_debug_log_start(boolean flag);
void an_config_debug_log(an_log_type_e type, an_debug_level_e lev, boolean flag);
extern const uint8_t * an_log_cfg_string[];
extern const uint8_t * an_log_lev_str[];
const uint8_t * an_get_log_str(an_log_type_e log);

void an_logger_init(void);
void an_logger_uninit(void);
void an_log_start(an_log_cfg_e cfg);
void an_log_stop(an_log_cfg_e cfg);
void an_log(an_log_type type, const uint8_t *fmt, ...);
void an_syslog (an_syslog_msg_e type, ...);
boolean an_log_is_enabled_for_type(an_log_type type);
boolean an_debug_log_is_enabled_for_type(an_log_type_e type);
boolean an_log_is_enabled_for_cfg(an_log_cfg_e cfg);
boolean an_log_is_enabled(void);
an_log_type_e an_get_log_type(uint8_t protocol_type, uint16_t msg_type);
#endif
