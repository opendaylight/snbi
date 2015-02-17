/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_H__
#define __AN_H__

#include "../al/an_types.h"
#include "../al/an_cert.h"

typedef enum an_global_cfg_state_e_ {

    AN_GLOBAL_CFG_STATE_DEFAULT,
    AN_GLOBAL_CFG_STATE_DISABLED,
    AN_GLOBAL_CFG_STATE_ENABLED,
    AN_GLOBAL_CFG_STATE_MAX

} an_global_cfg_state_e;

typedef enum an_protocol_type_e_ {

    AN_PROTO_CHANNEL_DISCOVERY  = 1,
    AN_PROTO_ADJACENCY_DISCOVERY,
    AN_PROTO_ACP,
    AN_PROTO_CNP,

    AN_PROTO_MAX

} an_protocol_type_e;

typedef enum an_proto_adjacency_discovery_msg_type_e_ {

        AN_ADJACENCY_DISCOVERY_HELLO = 1,
        AN_ADJACENCY_DISCOVERY_MAX

} an_proto_adjacency_discovery_msg_type_e;

typedef enum an_proto_channel_discovery_msg_type_e_ {

    AN_MSG_UNTRUSTED_L2_CHANNEL_HELLO_PROBE_REQ  = 1,
    AN_MSG_UNTRUSTED_L2_CHANNEL_HELLO_PROBE_RESP = 2,
    AN_MSG_UNTRUSTED_L2_CHANNEL_HELLO_PROBE_ACK = 3,
    AN_MSG_UNTRUSTED_L2_CHANNEL_HELLO_REFRESH = 4,
    AN_MSG_UNTRUSTED_L2_MAX 

} an_proto_channel_discovery_msg_type_e;

typedef enum an_msg_type_e_ {

    AN_MSG_ND_HELLO = 1, /* AN_ADJACENCY_DISCOVERY_HELLO  TODO */
    AN_MSG_ND_BYE,

    AN_MSG_ND_CERT_REQUEST,
    AN_MSG_ND_CERT_RESPONSE,

    AN_MSG_BS_INVITE,
    AN_MSG_BS_REJECT,
    AN_MSG_BS_REQUEST,
    AN_MSG_BS_RESPONSE,

    AN_MSG_BS_ENROLL_QUARANTINE,    
    AN_MSG_NBR_CONNECT,
    AN_MSG_NBR_RECONNECT,
    AN_MSG_NBR_JOIN,
    AN_MSG_NBR_LEAVE,
    AN_MSG_NBR_LOST,
    AN_MSG_NBR_MODIFY,

    AN_MSG_ACP_DATA,

    AN_MSG_IDP_INTENT,
    AN_MSG_IDP_ACK,
    AN_MSG_IDP_INTENT_VERSION,
    AN_MSG_IDP_INTENT_REQUEST,
    AN_MSG_SERVICE_INFO,
    AN_MSG_SERVICE_INFO_ACK,

    AN_MSG_CNP_SOLICIT,
    AN_MSG_CNP_ADVERTISEMENT,
    AN_MSG_CNP_PROPOSAL,
    AN_MSG_CNP_ACCEPT,
    AN_MSG_CNP_REJECT,
    AN_MSG_CNP_ERROR,
    AN_MSG_CNP_ACK,
    
    AN_MSG_ND_KEEP_ALIVE,
    
    /* NOTE: Kindly add the respective strings for the definitions added here
       in the *an_msg_name_s[] */
} an_msg_type_e;

typedef enum an_service_type_e_ {
    AN_SERVICE_AAA,
    AN_SERVICE_MAX
} an_service_type_e;

typedef enum an_msg_interest_e_ {
    AN_MSG_INT_UDI              =   1 << 0,
    AN_MSG_INT_SUDI             =   1 << 1,
    AN_MSG_INT_DOMAIN_CERT      =   1 << 2,
    AN_MSG_INT_DEVICE_ID        =   1 << 3,
    AN_MSG_INT_DOMAIN_ID        =   1 << 4,
    AN_MSG_INT_IF_IPADDR        =   1 << 5,
    AN_MSG_INT_IF_NAME          =   1 << 6,
    AN_MSG_INT_ANRA_CERT        =   1 << 7,
    AN_MSG_INT_CA_CERT          =   1 << 8,
    AN_MSG_INT_ANRA_IPADDR      =   1 << 9,
    AN_MSG_INT_ANRA_SIGN        =   1 << 10,
    AN_MSG_INT_UNSIGNED_CERT_REQ=   1 << 11,
    AN_MSG_INT_CERT_REQ_SIGN    =   1 << 12,
    AN_MSG_INT_CERT_RESP        =   1 << 13,
    AN_MSG_INT_PUB_KEY          =   1 << 14,
    AN_MSG_INT_IDP_VERSION      =   1 << 15,
    AN_MSG_INT_ACP_PAYLOAD      =   1 << 16,
    AN_MSG_INT_MASA_SIGN        =   1 << 17,
    AN_MSG_INT_SERVICE_INFO     =   1 << 18,
    AN_MSG_INT_NEW_NBR_LINK     =   1 << 19,
    AN_MSG_INT_ANR_ID           =   1 << 20,
    AN_MSG_INT_DEVICE_IPADDR    =   1 << 21,
	AN_MSG_INT_CNP_CAPABILITY   =   1 << 22,
	AN_MSG_INT_CNP_ERROR        =   1 << 23,
	AN_MSG_INT_SIGNED_CERT_REQ  =   1 << 24,
} an_msg_interest_e;

typedef struct an_service_info_t_ {
     an_service_type_e srvc_type;
     an_addr_t srvc_ip;
} an_service_info_t;

#define AN_DOMAIN_TP_LABEL "AN-Domain"
#define AN_DOMAIN_KEY_LABEL "AN-Domain"
#define AN_CERT_MAP_LABEL "AN-Cert-Map"
#define ANRA_CS_TP_LABEL "ANRA-CS"

#define AN_GENERIC_TIMER_INTERVAL (90 * 1000)

boolean is_an_initialised(void);

boolean an_is_device_enrollment_url_set(void);
boolean an_get_udi(an_udi_t *udi);
boolean an_get_domain_cert(an_cert_t *domain_cert);
boolean an_get_domain_cert_validity(an_cert_t *domain_cert);
uint8_t* an_get_device_id(void);
uint8_t* an_get_domain_id(void);
an_addr_t an_get_device_ip(void);
an_addr_t an_get_anra_ip(void);
an_afi_t an_get_afi(void);
an_iptable_t an_get_iptable(void);
an_if_t an_get_anra_if(void);
an_cert_t an_get_ca_cert(void);
an_network_prefix_t an_get_nw_prefix(void);
uint16_t an_get_routing_ospf_pid(void);
uint16_t an_get_routing_ospf_area(void);
uint32_t an_get_routing_ospf_rid(void);
an_routing_cfg_t an_get_routing_info(void);
an_rpl_info_t an_get_rpl_routing_info(void);
an_addr_t an_get_aaa_ip(void);
an_addr_t an_get_nms_ip(void);
an_key_t an_get_public_key(uint8_t *key_label);

void an_set_device_enrollment_url(boolean flag);
void an_set_udi(an_udi_t udi);
void an_set_device_id(uint8_t *device_id);
void an_set_domain_id(uint8_t *domain_id);
void an_set_domain_cert(an_cert_t domain_cert, an_cert_type_enum cert_type);
void an_set_device_ip(an_addr_t ip);
boolean an_set_service_info(an_service_type_e srvc_type, an_addr_t *srvc_ip);
void an_set_anra_ip(an_addr_t ip);
void an_set_afi(an_afi_t afi);
void an_set_iptable(an_iptable_t iptable);
void an_set_anra_if(an_if_t ifhndl);
void an_set_ca_cert(an_cert_t cert);
void an_reset_ca_cert(void);
void an_set_nw_prefix(an_network_prefix_t nw_prefix);
void an_set_routing_ospf_pid(uint16_t pid);
void an_set_routing_ospf_area(uint16_t area);
void an_set_routing_ospf_rid(uint32_t rid);
void an_set_rpl_routing_info(void);
void an_set_rpl_float_root_enable_flag(boolean);

void an_reset_an_info(void);
void an_reset_global_info(void);

void an_autonomic_enable(void);
void an_autonomic_disable(void);
void an_set_global_cfg_autonomic_enable(void);
void an_set_global_cfg_autonomic_disable(void);
void an_set_global_cfg_autonomic_default(void);
boolean an_is_global_cfg_autonomic_enabled(void);

void an_set_ike_cli_autonomically_created(boolean flag);

void an_reset_rpl_routing_info(void);

const uint8_t *an_get_msg_name(an_msg_type_e type);

/* currently works with 8 bit numbers */
//uint8_t an_itoa_len(uint8_t num);
//void an_itoa(uint8_t num, uint8_t *str);
//void an_concat_str_with_num(uint8_t *prefix_str, uint8_t suffix_num, uint8_t **str);

void an_start_cert_server(uint8_t *ca_server_label);
void an_stop_cert_server(uint8_t *ca_server_label);

//an_addr_t an_get_v6addr_from_names(uint8_t *domain_id, uint8_t *device_id);
an_v4addr_t an_get_v4addr_from_names(uint8_t *domain_id, uint8_t *device_id);

an_pak_t * an_pak_alloc (uint16_t pak_len);

/*  
 * AN_SET_BIT_FLAGS
 *  
 * Set the flags specified in "flags", in the flag variable in "flagvar"
 */     
#define AN_SET_BIT_FLAGS(flagvar, flags) (flagvar |= (ulong)(flags))

/* 
 * AN_CHECK_BIT_FLAGS
 *              
 * Check if *all* the flags specified in "flags" are set in "flagvar"
 */     
#define AN_CHECK_BIT_FLAGS(flagvar,flags) (((flagvar)&(ulong)(flags))==(ulong)(flags))
                 
/*               
 * AN_CLEAR_BIT_FLAGS
 *  
 * Clear the flags specified in "flags" from the flag variable "flagvar"
 */ 
#define AN_CLEAR_BIT_FLAGS(flagvar, flags) (flagvar &= (~((ulong)(flags))))
                   
/*
 * AN_SET_OR_CLEAR_BIT_FLAGS
 *
 * Depending on a boolean condition, either set or clear the specified
 * flags from the specified variable
 */
#define AN_SET_OR_CLEAR_BIT_FLAGS(flagvar, flags, condition) \
        if (condition) {AN_SET_BIT_FLAGS(flagvar, flags);} else \
    {AN_CLEAR_BIT_FLAGS(flagvar, flags);}

boolean an_hton_1_byte(uint8_t *target, int8_t src);
boolean an_hton_2_bytes(uint8_t *target, int16_t src);
boolean an_hton_4_bytes(uint8_t *target, int32_t src);
boolean an_hton_16_bytes(uint8_t *target, int32_t src[4]);

uint8_t *an_hton_1_byte_and_move(uint8_t *target, int8_t src);
uint8_t *an_hton_2_bytes_and_move(uint8_t *target, int16_t src);
uint8_t *an_hton_4_bytes_and_move(uint8_t *target, int32_t src);
uint8_t *an_hton_16_bytes_and_move(uint8_t *target, int32_t src[4]);

uint8_t  an_ntoh_1_byte(uint8_t *src);
uint16_t an_ntoh_2_bytes(uint8_t *src);
uint32_t an_ntoh_4_bytes(uint8_t *src);
boolean an_ntoh_16_bytes(uint32_t *target, uint8_t *src);

uint8_t *an_ntoh_1_byte_and_move(uint8_t *target, uint8_t *src);
uint8_t *an_ntoh_2_bytes_and_move(uint16_t *target, uint8_t *src);
uint8_t *an_ntoh_4_bytes_and_move(uint32_t *target, uint8_t *src);
uint8_t *an_ntoh_16_bytes_and_move(uint32_t *target, uint8_t *src);

an_global_cfg_state_e an_get_global_cfg_state(void);
void an_set_anr_macaddress(an_mac_addr *mac_address);
an_mac_addr * an_get_anr_macaddress(void);
void an_set_anr_ip_for_cert_renewal(an_addr_t ip);
an_addr_t an_get_anr_ip_for_cert_renewal(void);

#endif
