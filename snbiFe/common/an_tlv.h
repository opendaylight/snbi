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
    uint16_t msg_num;
    uint16_t reserved_2;
} an_header;

#define AN_MSG_ND_MASK  0xF0

typedef struct an_tlv_ {
    uint16_t type;
    uint16_t length;
    uint8_t value[0];
} an_tlv;

#define TLV_BYTE_OFFSET_TYPE 0
#define TLV_BYTE_OFFSET_STYPE 1
#define TLV_BYTE_OFFSET_LENGTH 2
#define TLV_BYTE_OFFSET_VALUE 4

#define AN_TLV_HDR_SIZE 4
#define AN_TLV_TYPE_LIMIT 255 

typedef enum an_cd_tlv_type_ {
    AN_CD_TLV_TYPE_INVALID,
    AN_CD_TLV_TYPE_UDI, 
    AN_CD_TLV_TYPE_IF_NAME,
    AN_CD_TLV_TYPE_DEST_UDI,
    AN_CD_TLV_TYPE_VLAN,
    AN_CD_TLV_TYPE_MAX, //Add Any new TLV above AN_CD_TLV_TYPE_MAX
} an_cd_tlv_type;

typedef enum an_nd_tlv_type_ {
    AN_ND_TLV_TYPE_INVALID,
    AN_ND_TLV_TYPE_UDI,
    AN_ND_TLV_TYPE_DEVICE_ID,
    AN_ND_TLV_TYPE_DOMAIN_ID,
    AN_ND_TLV_TYPE_DEVICE_V4ADDR,
    AN_ND_TLV_TYPE_DEVICE_V6ADDR,
    AN_ND_TLV_TYPE_IF_V4ADDR,
    AN_ND_TLV_TYPE_IF_V6ADDR,
    AN_ND_TLV_TYPE_IF_NAME,
    AN_ND_TLV_TYPE_MAX, //Add Any new TLV above AN_ND_TLV_TYPE_MAX
} an_nd_tlv_type;

typedef enum an_bs_tlv_type_ {
    AN_BS_TLV_TYPE_INVALID,
    AN_BS_TLV_TYPE_UDI, 
    AN_BS_TLV_TYPE_DEVICE_ID,
    AN_BS_TLV_TYPE_DOMAIN_ID,
    AN_BS_TLV_TYPE_IF_V4ADDR,
    AN_BS_TLV_TYPE_IF_V6ADDR,
    AN_BS_TLV_TYPE_UNSIGNED_CERT_REQ,
    AN_BS_TLV_TYPE_CERT_REQ_SIGN,
    AN_BS_TLV_TYPE_CERT_RESP,
    AN_BS_TLV_TYPE_PUBLIC_KEY,
    AN_BS_TLV_TYPE_ANRA_V4ADDR,
    AN_BS_TLV_TYPE_ANRA_V6ADDR,
    AN_BS_TLV_TYPE_ANRA_SIGN,
    AN_BS_TLV_TYPE_SUDI_CERTIFICATE,
    AN_BS_TLV_TYPE_DOMAIN_CERTIFICATE,
    AN_BS_TLV_TYPE_ANRA_CERTIFICATE,
    AN_BS_TLV_TYPE_CA_CERTIFICATE,
    AN_BS_TLV_TYPE_ANR_ID,
    AN_BS_TLV_TYPE_MASA_SIGN,
    AN_BS_TLV_TYPE_ACP_PAYLOAD,
    AN_BS_TLV_TYPE_DEST_UDI,
    AN_BS_TLV_TYPE_SERVICE,
    AN_BS_TLV_TYPE_IDP_VERSION,
    AN_BS_TLV_TYPE_SIGNED_CERT_REQ,
    AN_BS_TLV_TYPE_MAX, //Add Any new TLV above AN_BS_TLV_TYPE_MAX
} an_bs_tlv_type;

typedef enum an_cnp_tlv_type_ {
    AN_CNP_TLV_TYPE_INVALID,
    AN_CNP_TLV_TYPE_CAPABILITY,
    AN_CNP_TLV_TYPE_ERROR,
    AN_CNP_TLV_TYPE_MAX, //Add Any new TLV above AN_CNP_TLV_TYPE_MAX
} an_cnp_tlv_type;

typedef enum an_tlv_subtype_cert_ {
    AN_TLV_STYPE_SUDI               =   1,
    AN_TLV_STYPE_DOMAIN_CERT        =   2,
    AN_TLV_STYPE_ANRA_CERT          =   3,
    AN_TLV_STYPE_CA_CERT            =   4,
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
uint16_t an_tlv_get_length(uint8_t *tlv);
uint16_t an_tlv_calculate_padded_length(uint8_t *tlv);
uint8_t *an_tlv_get_value(uint8_t *tlv);
uint8_t *an_tlv_get_next_tlv(uint8_t *tlv);

/* Compose Routines */
void an_tlv_compose(uint8_t *buffer, uint16_t type, 
                    uint16_t value_length, uint8_t *value);
uint8_t * an_header_compose_and_move(uint8_t *buffer, an_header header);
uint8_t * an_tlv_compose_udi_and_move(uint8_t *buffer, an_udi_t udi, uint8_t proto_type);
uint8_t * an_tlv_compose_sudi_and_move(uint8_t *buffer, an_cert_t sudi, uint8_t proto_type);
uint8_t * an_tlv_compose_domain_cert_and_move(uint8_t *buffer, an_cert_t domain_cert, uint8_t proto_type);
uint8_t * an_tlv_compose_device_id_and_move(uint8_t *buffer, uint8_t *device_id, uint8_t proto_type);
uint8_t * an_tlv_compose_domain_id_and_move(uint8_t *buffer, uint8_t *domain_id, uint8_t proto_type);
uint8_t * an_tlv_compose_if_ipaddr_and_move(uint8_t *buffer, an_addr_t addr, uint8_t proto_type);
uint8_t * an_tlv_compose_if_name_and_move(uint8_t *buffer, uint8_t *if_name, uint8_t proto_type);
uint8_t * an_tlv_compose_device_ipaddr_and_move(uint8_t *buffer, an_addr_t addr, uint8_t proto_type);
uint8_t * an_tlv_compose_anra_ipaddr_and_move(uint8_t *buffer, an_addr_t addr, uint8_t proto_type);
uint8_t * an_tlv_compose_anra_sign_and_move(uint8_t *buffer, an_sign_t sign, uint8_t proto_type);
uint8_t * an_tlv_compose_masa_sign_and_move(uint8_t *buffer, an_sign_t sign, uint8_t proto_type);
uint8_t * an_tlv_compose_anra_cert_and_move(uint8_t *buffer, an_cert_t anra_cert, uint8_t proto_type);
uint8_t * an_tlv_compose_ca_cert_and_move(uint8_t *buffer, an_cert_t ca_cert, uint8_t proto_type);
uint8_t * an_tlv_compose_ospf_cfg_and_move (uint8_t *buffer, an_routing_cfg_t routing_info, uint8_t proto_type);
uint8_t * an_tlv_compose_unsigned_cert_request_and_move(uint8_t *buffer, an_cert_req_t signed_cert_request, uint8_t proto_type);
uint8_t * an_tlv_compose_signed_cert_request_and_move(uint8_t *buffer, an_cert_req_t signed_cert_request, uint8_t proto_type);
uint8_t * an_tlv_compose_cert_req_sign_and_move(uint8_t *buffer, an_sign_t cert_req_sign, uint8_t proto_type);
uint8_t * an_tlv_compose_public_key_and_move(uint8_t *buffer, an_key_t public_key, uint8_t proto_type);
uint8_t * an_tlv_compose_intent_version_and_move (uint8_t *buffer, an_intent_ver_t version, uint8_t proto_type);
uint8_t * an_tlv_compose_acp_client_data_and_move(uint8_t *buffer, an_payload_t payload, uint8_t proto_type);
uint8_t * an_tlv_compose_service_info_data_and_move (uint8_t *buffer, 
                                                  an_service_info_t *srvc_info, uint8_t proto_type);
uint8_t * an_tlv_compose_cnp_capability_data_and_move(uint8_t *buffer, 
                                                    an_cnp_capability_t cnp_capability, uint8_t proto_type);
uint8_t * an_tlv_compose_cnp_error_data_and_move (uint8_t *buffer,
                                                  an_cnp_cap_error_t cnp_error, uint8_t proto_type);
const uint8_t * an_tlv_get_tlv_type_str(uint8_t *tlv, an_protocol_type_e proto_type);
uint8_t * an_tlv_compose_anr_id_and_move(uint8_t *buffer, an_mac_addr *mac_address, uint8_t proto_type);
#endif
