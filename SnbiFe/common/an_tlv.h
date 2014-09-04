/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_TLV_H__
#define __AN_TLV_H__

#include "../al/an_addr.h"
#include "an.h"
#include "an_nbr_db.h"

typedef enum an_protocol_type {
    AN_PROTOCOL_TYPE_ACP,
    AN_PROTOCOL_TYPE_MAX
} an_protocol_type;

typedef struct an_header_ {
    uint8_t ver:4;
    uint8_t reserved:4;
    uint8_t protocol_type;
    uint8_t flags;
    uint8_t hop_limit;
    uint16_t msg_type;
    uint16_t length;
} an_header;

#define AN_MSG_ND_MASK  0xF0

typedef struct an_tlv_ {
    uint8_t type;
    uint8_t sub_type;
    uint16_t length;
    uint8_t value[0];
} an_tlv;

#define TLV_BYTE_OFFSET_TYPE 0
#define TLV_BYTE_OFFSET_STYPE 1
#define TLV_BYTE_OFFSET_LENGTH 2
#define TLV_BYTE_OFFSET_VALUE 4

#define AN_TLV_HDR_SIZE 4
#define AN_TLV_TYPE_LIMIT 255 
#define AN_STLV_TYPE_LIMIT 255

typedef enum an_tlv_type_ {
    AN_TLV_TYPE_UDI     = 1,
    AN_TLV_TYPE_NONCE,
    AN_TLV_TYPE_CERTIFICATE,
    AN_TLV_TYPE_DEVICE_ID,
    AN_TLV_TYPE_DOMAIN_ID,
    AN_TLV_TYPE_IF_IPADDR,
    AN_TLV_TYPE_IF_NAME,
    AN_TLV_TYPE_DEVICE_IPADDR,
    AN_TLV_TYPE_ANRA_IPADDR,
    AN_TLV_TYPE_ANRA_SIGN,
    AN_TLV_TYPE_NW_PREFIX,
    AN_TLV_TYPE_ROUTING_CFG,
    AN_TLV_TYPE_CERT_REQ,
    AN_TLV_TYPE_CERT_REQ_SIGN,
    AN_TLV_TYPE_CERT_RESP,
    AN_TLV_TYPE_PUBLIC_KEY,
    AN_TLV_TYPE_IDP_VERSION,
    AN_TLV_TYPE_ACP_PAYLOAD,
    AN_TLV_TYPE_MASA_SIGN,
    AN_TLV_TYPE_SERVICE,
    AN_TLV_TYPE_DEST_UDI,
    AN_TLV_TYPE_INVALID,
} an_tlv_type;

typedef enum an_tlv_subtype_cert_ {
    AN_TLV_STYPE_SUDI               =   1,
    AN_TLV_STYPE_DOMAIN_CERT        =   2,
    AN_TLV_STYPE_ANRA_CERT          =   3,
} an_tlv_subtype_cert;

typedef enum an_tlv_subtype_ipaddr_ {
    AN_TLV_STYPE_IPV4_ADDR          =   1,
    AN_TLV_STYPE_IPV6_ADDR          =   2,
} an_tlv_subtype_ipaddr;

typedef enum an_tlv_subtype_sign_ {
    AN_TLV_STYPE_RSA                =   1,
} an_tlv_subtype_sign;

typedef enum an_tlv_subtype_ospf_cfg_ {
    AN_TLV_STYPE_OSPF               =   1,
    AN_TLV_STYPE_EIGRP              =   2,
    AN_TLV_STYPE_ISIS               =   3,
} an_tlv_subtype_ospf_cfg;

typedef enum an_tlv_subtype_service_ {
    AN_TLV_STYPE_AAA,
    AN_TLV_STYPE_MAX
} an_tlv_subtype_service;

/* Access Routines */
uint8_t an_tlv_get_type(uint8_t *tlv);
uint8_t an_tlv_get_subtype(uint8_t *tlv);
uint16_t an_tlv_get_length(uint8_t *tlv);
uint16_t an_tlv_calculate_padded_length(uint8_t *tlv);
uint8_t *an_tlv_get_value(uint8_t *tlv);
uint8_t *an_tlv_get_next_tlv(uint8_t *tlv);

/* Compose Routines */
void an_tlv_compose(uint8_t *buffer, uint8_t type, uint8_t stype, 
                    uint16_t value_length, uint8_t *value);
uint8_t * an_header_compose_and_move(uint8_t *buffer, an_header header);
uint8_t * an_tlv_compose_udi_and_move(uint8_t *buffer, an_udi_t udi);
uint8_t * an_tlv_compose_sudi_and_move(uint8_t *buffer, an_cert_t sudi);
uint8_t * an_tlv_compose_domain_cert_and_move(uint8_t *buffer, an_cert_t domain_cert);
uint8_t * an_tlv_compose_device_id_and_move(uint8_t *buffer, uint8_t *device_id);
uint8_t * an_tlv_compose_domain_id_and_move(uint8_t *buffer, uint8_t *domain_id);
uint8_t * an_tlv_compose_if_ipaddr_and_move(uint8_t *buffer, an_addr_t addr);
uint8_t * an_tlv_compose_if_name_and_move(uint8_t *buffer, uint8_t *if_name);
uint8_t * an_tlv_compose_device_ipaddr_and_move(uint8_t *buffer, an_addr_t addr);
uint8_t * an_tlv_compose_anra_ipaddr_and_move(uint8_t *buffer, an_addr_t addr);
uint8_t * an_tlv_compose_anra_sign_and_move(uint8_t *buffer, an_sign_t sign);
uint8_t * an_tlv_compose_masa_sign_and_move(uint8_t *buffer, an_sign_t sign);
uint8_t * an_tlv_compose_anra_cert_and_move(uint8_t *buffer, an_cert_t anra_cert);
uint8_t * an_tlv_compose_ospf_cfg_and_move (uint8_t *buffer, an_routing_cfg_t routing_info);
uint8_t * an_tlv_compose_cert_request_and_move(uint8_t *buffer, an_cert_req_t cert_request);
uint8_t * an_tlv_compose_cert_req_sign_and_move(uint8_t *buffer, an_sign_t cert_req_sign);
uint8_t * an_tlv_compose_public_key_and_move(uint8_t *buffer, an_key_t public_key);
uint8_t * an_tlv_compose_intent_version_and_move (uint8_t *buffer, an_intent_ver_t version);
uint8_t * an_tlv_compose_acp_client_data_and_move(uint8_t *buffer, an_payload_t payload);
uint8_t * an_tlv_compose_service_info_data_and_move (uint8_t *buffer, 
                                                  an_service_info_t *srvc_info);
const uint8_t * an_tlv_get_tlv_type_str(uint8_t *tlv);
const uint8_t * an_tlv_get_tlv_subtype_str(uint8_t *tlv);
#endif
