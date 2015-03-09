/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "an.h"
#include "an_tlv.h"
#include "an_acp.h"
#include "an_idp.h"
#include "../al/an_addr.h"
#include "../al/an_logger.h"
#include "../al/an_mem.h"
#include "../al/an_str.h"

extern an_log_type_e an_get_log_type (an_header *header);

static const uint8_t *an_cd_tlv_type_str[] = {
    "Invalid",
    "Udi",
    "IF Name",
    "Dest Udi",
    "Max",
};

static const uint8_t *an_nd_tlv_type_str[] = {
    "Invalid",
    "Udi",
    "Device Id",
    "Domain Id",
    "Device V4addr",
    "Device V6addr",
    "IF V4addr",
    "IF V6addr",
    "IF Name",
    "Max",
};


static const uint8_t *an_bs_tlv_type_str[] = {
    "Invalid",
    "Udi",
    "Device Id",
    "Domain Id",
    "IF V4addr",
    "IF V6addr",
    "Unsigned Cert Req",
    "Cert Req Sign",
    "Cert Response",
    "Public Key",
    "Registrar V4addr",
    "Registrar V6addr",
    "Registrar Sign",
    "Sudi Cert",
    "Domain Cert",
    "Registrar Cert",   
    "CA Cert",
    "Registrar ID", 
    "MASA Sign",
    "Payload",
    "Dest Udi",
    "Service",
    "IDP version",
	"Signed Cert Request",
    "Max",
};

static const uint8_t *an_cnp_tlv_type_str[] = {
    "Invalid",
    "CNP Capability",
    "CNP Error",
    "Max",
};


const uint8_t * 
an_tlv_get_tlv_type_str (uint8_t *tlv, an_protocol_type_e proto_type) 
{
    if (proto_type == AN_PROTO_CHANNEL_DISCOVERY) {
        return (an_cd_tlv_type_str[an_tlv_get_type(tlv)]);
    }
    
    if (proto_type == AN_PROTO_ADJACENCY_DISCOVERY) {
        return (an_nd_tlv_type_str[an_tlv_get_type(tlv)]);
    }
    
    if (proto_type == AN_PROTO_ACP) {
        return (an_bs_tlv_type_str[an_tlv_get_type(tlv)]);
    }
            
    if (proto_type == AN_PROTO_CNP) {
        return (an_cnp_tlv_type_str[an_tlv_get_type(tlv)]);
    }
    
    return ("Invalid");
}

uint8_t 
an_tlv_get_type (uint8_t *tlv) {
            
    if (!tlv) {
        return (0);
    }
    
    return (an_ntoh_2_bytes(tlv + TLV_BYTE_OFFSET_TYPE));
}

uint16_t 
an_tlv_get_length (uint8_t *tlv) 
{
    if (!tlv) {
        return (0);
    }

    return (an_ntoh_2_bytes(tlv + TLV_BYTE_OFFSET_LENGTH));
}

uint8_t *
an_tlv_get_value (uint8_t *tlv)
{
    if (!tlv) {
        return (0);
    }
    
    return (tlv + TLV_BYTE_OFFSET_VALUE);
}

uint8_t *
an_tlv_get_next_tlv (uint8_t *tlv)
{
    if (!tlv) {
        return (NULL);
    }

    return (tlv + an_tlv_get_length(tlv)); 
}

void
an_tlv_compose (uint8_t *buffer, uint16_t type, 
                uint16_t value_length, uint8_t* value)
{
    uint8_t *tlv = NULL;

    if (!buffer) {
        return;
    }
    
    tlv = buffer;

    tlv = an_hton_2_bytes_and_move(tlv, type);
    tlv = an_hton_2_bytes_and_move(tlv, value_length + AN_TLV_HDR_SIZE);
    if (value_length) {    
        an_memcpy_guard_s(tlv, value_length, value, value_length);
    }
}

uint8_t *
an_header_compose_and_move (uint8_t *buffer, an_header header)
{
    uint8_t *buffer_p = NULL;
    an_log_type_e log;

    if (!buffer) {
        return (NULL);
    }

    log = an_get_log_type(&header);
    
    buffer_p = buffer;    

    buffer_p = an_hton_1_byte_and_move(buffer_p, 
                                header.reserved | (header.ver << 4));
    buffer_p = an_hton_1_byte_and_move(buffer_p, 
                                header.protocol_type);
    buffer_p = an_hton_1_byte_and_move(buffer_p, header.flags);
    buffer_p = an_hton_1_byte_and_move(buffer_p, header.hop_limit);
    buffer_p = an_hton_2_bytes_and_move(buffer_p, header.msg_type);
    buffer_p = an_hton_2_bytes_and_move(buffer_p, header.length);
    buffer_p = an_hton_2_bytes_and_move(buffer_p, header.msg_num);
    buffer_p = an_hton_2_bytes_and_move(buffer_p, header.reserved_2);
    
    DEBUG_AN_LOG(log, AN_DEBUG_INFO, NULL, 
                 "\n%sComposed AN header of len = [%d] bytes" , 
                 an_get_log_str(log), buffer_p - buffer);

    return (buffer_p);
}

uint8_t *
an_tlv_compose_udi_and_move (uint8_t *buffer, an_udi_t udi, 
                             uint8_t proto_type)
{
    uint16_t tlv_type = 0;

    if (!buffer) {
        return (NULL);
    }
    
    if (!udi.len) {
        return (buffer);
    }

    if (proto_type == AN_PROTO_ADJACENCY_DISCOVERY) {
        tlv_type = AN_ND_TLV_TYPE_UDI;
    } else if (proto_type == AN_PROTO_ACP) {
        tlv_type = AN_BS_TLV_TYPE_UDI;
    }

    an_tlv_compose(buffer, tlv_type, udi.len, udi.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_sudi_and_move (uint8_t *buffer, an_cert_t sudi, 
                              uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }
    
    an_tlv_compose(buffer, AN_BS_TLV_TYPE_SUDI_CERTIFICATE, sudi.len, sudi.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_domain_cert_and_move (uint8_t *buffer, an_cert_t domain_cert,
                                     uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }
    
    an_tlv_compose(buffer, AN_BS_TLV_TYPE_DOMAIN_CERTIFICATE, domain_cert.len, 
                   domain_cert.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_device_id_and_move (uint8_t *buffer, uint8_t *device_id, 
                                   uint8_t proto_type)
{
    uint16_t tlv_type = 0;
    if (!buffer) {
        return (NULL);
    }
    
    if (proto_type == AN_PROTO_ADJACENCY_DISCOVERY) {
        tlv_type = AN_ND_TLV_TYPE_DEVICE_ID;
    } else if (proto_type == AN_PROTO_ACP) {
        tlv_type = AN_BS_TLV_TYPE_DEVICE_ID;
    }

    an_tlv_compose(buffer, tlv_type, 
                   1+an_strlen(device_id), device_id);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_domain_id_and_move (uint8_t *buffer, uint8_t *domain_id, 
                                   uint8_t proto_type)
{
    uint16_t tlv_type = 0;
    if (!buffer) {
        return (NULL);
    }
    
    if (proto_type == AN_PROTO_ADJACENCY_DISCOVERY) {
        tlv_type = AN_ND_TLV_TYPE_DOMAIN_ID;
    } else if (proto_type == AN_PROTO_ACP) {
        tlv_type = AN_BS_TLV_TYPE_DOMAIN_ID;
    }

    an_tlv_compose(buffer, tlv_type, 
                   1+an_strlen(domain_id), domain_id);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_if_ipaddr_and_move (uint8_t *buffer, an_addr_t address, 
                                   uint8_t proto_type)
{
    uint16_t tlv_type = 0;
    an_v4addr_t v4addr = AN_V4ADDR_ZERO;
    an_v6addr_t v6addr = AN_V6ADDR_ZERO;
    uint8_t *addr = NULL;

    if (!buffer) {
        return (NULL);
    }
    
    if (an_addr_is_v4(address)) {
        v4addr = an_addr_v4ton(address); 
        addr = (uint8_t *)&v4addr;

        if (proto_type == AN_PROTO_ADJACENCY_DISCOVERY) {
            tlv_type = AN_ND_TLV_TYPE_IF_V4ADDR;
        } else if (proto_type == AN_PROTO_ACP) {
            tlv_type = AN_BS_TLV_TYPE_IF_V4ADDR;
        }

        an_tlv_compose(buffer, tlv_type,
                       sizeof(v4addr), addr);
    } else {
        v6addr = an_addr_v6ton(address); 
        addr = (uint8_t *)&v6addr;

        if (proto_type == AN_PROTO_ADJACENCY_DISCOVERY) {
            tlv_type = AN_ND_TLV_TYPE_IF_V6ADDR;
        } else if (proto_type == AN_PROTO_ACP) {
            tlv_type = AN_BS_TLV_TYPE_IF_V6ADDR;
        }

        an_tlv_compose(buffer, tlv_type,
                       sizeof(v6addr), addr);
    }
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_if_name_and_move (uint8_t *buffer, uint8_t *if_name, 
                                 uint8_t proto_type)
{
    uint16_t tlv_type = 0;

    if (!buffer) {
        return (NULL);
    }
    
    if (proto_type == AN_PROTO_CHANNEL_DISCOVERY) {
        tlv_type = AN_CD_TLV_TYPE_IF_NAME;
    } else if (proto_type == AN_PROTO_ADJACENCY_DISCOVERY) {
        tlv_type = AN_ND_TLV_TYPE_IF_NAME;
    }

    
    an_tlv_compose(buffer, tlv_type, 
                   1 + an_strnlen_s(if_name, 99), if_name);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_device_ipaddr_and_move (uint8_t *buffer, an_addr_t address, 
                                       uint8_t proto_type)
{
    uint16_t tlv_type = 0;
    an_v4addr_t v4addr = AN_V4ADDR_ZERO;
    an_v6addr_t v6addr = AN_V6ADDR_ZERO;
    uint8_t *addr = NULL;

    if (!buffer) {
        return (NULL);
    }
    
    if (an_addr_is_v4(address)) {
        v4addr = an_addr_v4ton(address); 
        addr = (uint8_t *)&v4addr;
        if (proto_type == AN_PROTO_ADJACENCY_DISCOVERY) {
            tlv_type = AN_ND_TLV_TYPE_DEVICE_V4ADDR;
        }
        
        an_tlv_compose(buffer, tlv_type, sizeof(v4addr), addr);
    } else {
        v6addr = an_addr_v6ton(address); 
        addr = (uint8_t *)&v6addr;
        if (proto_type == AN_PROTO_ADJACENCY_DISCOVERY) {
            tlv_type = AN_ND_TLV_TYPE_DEVICE_V6ADDR;
        }
        an_tlv_compose(buffer, tlv_type, sizeof(v6addr), addr);
    }
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_anra_ipaddr_and_move (uint8_t *buffer, an_addr_t address, 
                                     uint8_t proto_type)
{
    uint16_t tlv_type = 0;
    an_v4addr_t v4addr = AN_V4ADDR_ZERO;
    an_v6addr_t v6addr = AN_V6ADDR_ZERO;
    uint8_t *addr = NULL;

    if (!buffer) {
        return (NULL);
    }
    
    if (an_addr_is_v4(address)) {
        v4addr = an_addr_v4ton(address); 
        addr = (uint8_t *)&v4addr;
        if (proto_type == AN_PROTO_ACP) {
            tlv_type = AN_BS_TLV_TYPE_ANRA_V4ADDR;
        }
        an_tlv_compose(buffer, tlv_type, sizeof(v4addr), addr);
    } else {
        v6addr = an_addr_v6ton(address); 
        addr = (uint8_t *)&v6addr;
        if (proto_type == AN_PROTO_ACP) {
            tlv_type = AN_BS_TLV_TYPE_ANRA_V6ADDR;
        }
        an_tlv_compose(buffer, tlv_type, sizeof(v6addr), addr);
    }
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_anra_sign_and_move (uint8_t *buffer, an_sign_t sign, 
                                   uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!sign.data || !sign.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_ANRA_SIGN, sign.len, sign.data);
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_masa_sign_and_move (uint8_t *buffer, an_sign_t sign, 
                                   uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }

    if (!sign.data || !sign.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_MASA_SIGN, sign.len, sign.data);
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_anra_cert_and_move (uint8_t *buffer, an_cert_t anra_cert, 
                                   uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!anra_cert.data || !anra_cert.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_ANRA_CERTIFICATE,
                   anra_cert.len, anra_cert.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_ca_cert_and_move (uint8_t *buffer, an_cert_t ca_cert, 
                                 uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!ca_cert.data || !ca_cert.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_CA_CERTIFICATE,
                   ca_cert.len, ca_cert.data);

    return (an_tlv_get_next_tlv(buffer));
}

#if 0
uint8_t *
an_tlv_compose_ospf_cfg_and_move (uint8_t *buffer, an_routing_cfg_t routing_info,
                                  uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!routing_info.ospf_pid) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_TLV_TYPE_ROUTING_CFG,
                   sizeof(an_routing_cfg_t), (uint8_t *)&routing_info);

    return (an_tlv_get_next_tlv(buffer));
}
#endif

uint8_t *
an_tlv_compose_unsigned_cert_request_and_move (uint8_t *buffer, an_cert_req_t cert_req, 
                                      uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!cert_req.data || !cert_req.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_UNSIGNED_CERT_REQ, 
                   cert_req.len, cert_req.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_signed_cert_request_and_move (uint8_t *buffer, 
						an_cert_req_t signed_cert_req, 
						uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!signed_cert_req.data || !signed_cert_req.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_SIGNED_CERT_REQ, 
                   signed_cert_req.len, signed_cert_req.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_cert_req_sign_and_move (uint8_t *buffer, an_sign_t cert_req_sign,
									   uint8_t proto)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!cert_req_sign.data || !cert_req_sign.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_CERT_REQ_SIGN,
                   cert_req_sign.len, cert_req_sign.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_public_key_and_move (uint8_t *buffer, an_key_t public_key, 
                                    uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!public_key.data || !public_key.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_PUBLIC_KEY, 
                   public_key.len, public_key.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_intent_version_and_move (uint8_t *buffer, an_intent_ver_t version,
                                        uint8_t proto_type)
{
    an_intent_ver_t version_in_nw_order = 0;

    if (!buffer) {
        return (NULL);
    }
    
    if (!version) {
        return (buffer);
    }

    an_idp_hton_version(&version_in_nw_order, version);

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_IDP_VERSION, 
                   sizeof(an_intent_ver_t), (uint8_t *)&version_in_nw_order);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_service_info_data_and_move (uint8_t *buffer, 
            an_service_info_t *srvc_info, uint8_t proto_type)
{
    an_v4addr_t v4addr = AN_V4ADDR_ZERO;
    an_v6addr_t v6addr = AN_V6ADDR_ZERO;
    uint8_t *addr = NULL;
    uint8_t addr_len = 0;

    if (!buffer) {
        return (NULL);
    }

    if (srvc_info->srvc_type < AN_SERVICE_AAA || 
        srvc_info->srvc_type >= AN_SERVICE_MAX) {
        an_log(AN_LOG_SRVC,"\n%sInvalid Service type", an_srvc_prefix);
        return (buffer);
    }

    if (!an_addr_get_len(srvc_info->srvc_ip)) {
         /* Return unchanged buffer */
        return (buffer);
    }

    if (an_addr_is_v4(srvc_info->srvc_ip)) {
        v4addr = an_addr_v4ton(srvc_info->srvc_ip); 
        addr = (uint8_t *)&v4addr;
        addr_len = AN_ADDRLEN_IP;
    } else if (an_addr_is_v6(srvc_info->srvc_ip)) {
        v6addr = an_addr_v6ton(srvc_info->srvc_ip); 
        addr = (uint8_t *)&v6addr;
        addr_len = AN_ADDRLEN_IPV6;
    } else {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_SERVICE,
              addr_len, addr);
    
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_cnp_error_data_and_move (uint8_t *buffer,
                                        an_cnp_cap_error_t cnp_error,
                                        uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!cnp_error.data || !cnp_error.len) {
        return (buffer);
    }
    
    an_tlv_compose(buffer, AN_CNP_TLV_TYPE_ERROR, 
                   cnp_error.len, cnp_error.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t * 
an_tlv_compose_cnp_capability_data_and_move (uint8_t *buffer,
                                             an_cnp_capability_t cnp_capability,
                                             uint8_t proto_type) 
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!cnp_capability.data || !cnp_capability.len) {
        return (buffer);
    }
    
    an_tlv_compose(buffer, AN_CNP_TLV_TYPE_CAPABILITY,
                   cnp_capability.len, cnp_capability.data);
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_acp_client_data_and_move (uint8_t *buffer, 
            an_payload_t payload, uint8_t proto_type)
{

    if (!buffer) {
        return (NULL);
    }

    if (!payload.data || !payload.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_ACP_PAYLOAD,
                   payload.len, payload.data);
    
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_anr_id_and_move(uint8_t *buffer, an_mac_addr *mac_address, 
                               uint8_t proto_type)
{
    if (!buffer) {
        return (NULL);
    }

    an_tlv_compose(buffer, AN_BS_TLV_TYPE_ANR_ID,
                   1+an_strlen(mac_address), mac_address);

    return (an_tlv_get_next_tlv(buffer));
}
