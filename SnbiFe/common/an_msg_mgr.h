/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_MSG_MGR_H__
#define __AN_MSG_MGR_H__

#include "../al/an_types.h"
#include "../al/an_sign.h"
#include "../al/an_sign.h"
#include "../al/an_logger.h"
#include "an_tlv.h"
#include "an.h"

#define AN_IPV6_VERSION 6
#define AN_IPV6_HDR_SIZE sizeof(an_ipv6_hdr_t)
#define AN_UDP_HDR_SIZE sizeof(an_udp_hdr_t)
#define AN_IPV6_PROTOCOL 180
#define AN_UDP_PROTOCOL 17
#define AN_UDP_PORT 8888
#define AN_DEFAULT_HOP_LIMIT 255
#define AN_DEFAULT_TOS 0
#define AN_DEFAULT_FLOW_LABEL 0 

typedef enum an_msg_delivery_e_ {
    AN_MSG_DELIVERY_IPV6    = 1,
    AN_MSG_DELIVERY_UDP     = 2,
} an_msg_delivery_e;

typedef enum an_nd_delivery_e_ {
    AN_ND_DELIVERY_IPV6_ND  = 1,
    AN_ND_DELIVERY_UDP      = 2,
} an_nd_delivery_e;

extern an_msg_delivery_e an_msg_delivery;
extern an_nd_delivery_e an_nd_delivery;

typedef struct an_msg_package_ {
    an_header header;
    an_cert_t sudi;
    an_cert_t domain_cert;
    uint8_t *device_id;
    uint8_t *domain_id;
    an_addr_t if_ipaddr;
    uint8_t *if_name;
    an_addr_t device_ipaddr;
    an_network_prefix_t domain_prefix;
    an_addr_t anra_ipaddr;
    an_cert_t anra_cert;
    an_sign_t anra_sign;
    an_cert_req_t cert_request;
    an_sign_t cert_req_sign;
    an_key_t public_key;
    an_routing_cfg_t routing_info;
    an_intent_ver_t intent_version;
    an_payload_t payload;
    an_udi_t udi;
    an_service_info_t srvc_info;

    an_msg_interest_e interest;
    an_iptable_t iptable; 
    an_addr_t src;
    an_addr_t dest;
    an_if_t ifhndl;
    an_sign_t masa_sign;
} an_msg_package;


void
an_msg_mgr_init_header(an_msg_package *msg_package, 
                       uint16_t protocol_type,
                       uint16_t msg_type);
boolean an_msg_mgr_incoming_ipv6_na(an_pak_t *pak, an_if_t ifhndl, 
                        an_ipv6_hdr_t *ipv6_hdr, an_icmp6_hdr_t *icmp6_hdr);
boolean an_msg_mgr_outgoing_ipv6_na(an_pak_t *pak, an_if_t ifhndl, 
                        an_ipv6_hdr_t *ipv6_hdr, an_icmp6_hdr_t *icmp6_hdr);
boolean
an_msg_mgr_receive_an_message(uint8_t *msg_block, an_pak_t *pak, an_if_t ifhndl);

an_msg_package* an_msg_mgr_get_empty_message_package(void);
void an_msg_mgr_free_message_package (an_msg_package *msg_package);

uint8_t *
an_msg_mgr_create_message_block_in_packet (an_pak_t **pak_out,
                        an_msg_package *message, uint16_t msg_len);
void
an_msg_mgr_close_message_block_in_packet (an_pak_t *pak, uint8_t *msg_block,
                                          uint16_t msg_len);

void an_msg_mgr_log_message(an_msg_package *msg_package, an_log_type_e log);
void an_msg_mgr_incoming_message(an_pak_t *pak);
void an_msg_mgr_send_message(an_msg_package *msg_package);
boolean
an_msg_mgr_deliver_outgoing_message (an_pak_t *pak, an_msg_package *msg_package);

boolean
an_msg_mgr_compose_message (uint8_t *msg_block, an_msg_package *msg_package);
uint16_t
an_msg_mgr_calculate_msg_len (an_msg_package *msg_package);

boolean an_msg_mgr_add_anra_signature(an_msg_package *msg_package);
boolean an_msg_mgr_verify_anra_signature(an_msg_package *msg_package, an_cert_t cert);

void an_certificate_display(const an_cert_t cert, const an_log_type_e log_type);
#endif
