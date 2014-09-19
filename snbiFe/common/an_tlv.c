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
#include "../al/an_addr.h"
#include "../al/an_logger.h"
#include "../al/an_mem.h"
#include "../al/an_str.h"


static const uint8_t *an_tlv_type_str[] = {
    
    "Invalid",
    "Udi",
    "Nonce",
    "Certificate",
    "Device Id",
    "Domain Id",
    "IF IPAddr",
    "IF Name",
    "Dev IPAddr",
    "AN Registrar IPAddr",
    "Registrar Sign",
    "N/w Prefix",
    "Routing Cfg",
    "Cert Req",
    "Cert Req Sign",
    "Cert Response",
    "Public Key",
    "Idp Version",
    "ACP Payload",
    "Masa Sign",
    "Service",
};

const uint8_t * 
an_tlv_get_tlv_type_str (uint8_t *tlv) 
{
    return (an_tlv_type_str[an_tlv_get_type(tlv)]);
}

static const uint8_t *an_tlv_subtype_str[][4] = {
    
    { "Default", "Default", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "Sudi", "Domain Cert", "Registrar Cert" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "IPv4 Addr", "IPv6 Addr", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "OSPF", "EIGRP", "IS-IS" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "RSA", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "Default", "Default", "Default", "Default" },
    { "AAA", "MAX" },
    { "Default", "Default", "Default", "Default" }

};
    
const uint8_t *an_tlv_get_tlv_subtype_str(uint8_t *tlv) 
{
    return (an_tlv_subtype_str[an_tlv_get_type(tlv)][an_tlv_get_subtype(tlv)]);
}
    
uint8_t
an_tlv_get_type (uint8_t *tlv) {
            
    if (!tlv) {
        return (0);
    }
    
    return (an_ntoh_1_byte(tlv + TLV_BYTE_OFFSET_TYPE));
}

uint8_t 
an_tlv_get_subtype (uint8_t *tlv)
{
    if (!tlv) {
        return (0);
    }
    
    return (an_ntoh_1_byte(tlv + TLV_BYTE_OFFSET_STYPE));
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
an_tlv_compose (uint8_t *buffer, uint8_t type, uint8_t stype, 
                uint16_t value_length, uint8_t* value)
{
    uint8_t *tlv = NULL;

    if (!buffer) {
        return;
    }
    //TBD- will not get header like this - call an_msg_mgr_parse_header

//    an_log_type_e log;
//    log = an_get_log_type((an_header *)buffer);
    
    tlv = buffer;

    tlv = an_hton_1_byte_and_move(tlv, type);
    tlv = an_hton_1_byte_and_move(tlv, stype);
    tlv = an_hton_2_bytes_and_move(tlv, value_length + AN_TLV_HDR_SIZE);
    an_memcpy_guard(tlv, value, value_length);
    
  /*  DEBUG_AN_LOG(log, AN_DEBUG_INFO, NULL, "\n%sComposed TLV of Type %s, "
                "Tlv Subtype - %s, Len = %d", 
                an_get_log_str(log), an_tlv_get_tlv_type_str(buffer), 
                an_tlv_get_tlv_subtype_str(buffer), an_tlv_get_length(buffer));
  */
}

uint8_t *
an_header_compose_and_move (uint8_t *buffer, an_header header)
{
    uint8_t *buffer_p = NULL;
    an_log_type_e log;

    if (!buffer) {
        return (NULL);
    }

    log = an_get_log_type(header.protocol_type, header.msg_type);
    
    buffer_p = buffer;    

    buffer_p = an_hton_1_byte_and_move(buffer_p, 
                                header.reserved | (header.ver << 4));
    buffer_p = an_hton_1_byte_and_move(buffer_p, 
                                header.protocol_type);
    buffer_p = an_hton_1_byte_and_move(buffer_p, header.flags);
    buffer_p = an_hton_1_byte_and_move(buffer_p, header.hop_limit);
    buffer_p = an_hton_2_bytes_and_move(buffer_p, header.msg_type);
    buffer_p = an_hton_2_bytes_and_move(buffer_p, header.length);
    
    DEBUG_AN_LOG(log, AN_DEBUG_INFO, NULL, 
                 "\n%sComposed AN header of len = [%d] bytes" , 
                 an_get_log_str(log), buffer_p - buffer);

    return (buffer_p);
}

uint8_t *
an_tlv_compose_udi_and_move (uint8_t *buffer, an_udi_t udi)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!udi.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_TLV_TYPE_UDI, 1, 
                   udi.len, udi.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_sudi_and_move (uint8_t *buffer, an_cert_t sudi)
{
    if (!buffer) {
        return (NULL);
    }
    
    an_tlv_compose(buffer, AN_TLV_TYPE_CERTIFICATE, AN_TLV_STYPE_SUDI, 
                   sudi.len, sudi.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_domain_cert_and_move (uint8_t *buffer, an_cert_t domain_cert)
{
    if (!buffer) {
        return (NULL);
    }
    
    an_tlv_compose(buffer, AN_TLV_TYPE_CERTIFICATE, AN_TLV_STYPE_DOMAIN_CERT, 
                   domain_cert.len, domain_cert.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_device_id_and_move (uint8_t *buffer, uint8_t *device_id)
{
    if (!buffer) {
        return (NULL);
    }
    
    an_tlv_compose(buffer, AN_TLV_TYPE_DEVICE_ID, 1, 
                   1+an_strlen(device_id), device_id);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_domain_id_and_move (uint8_t *buffer, uint8_t *domain_id)
{
    if (!buffer) {
        return (NULL);
    }
    
    an_tlv_compose(buffer, AN_TLV_TYPE_DOMAIN_ID, 1, 
                   1+an_strlen(domain_id), domain_id);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_if_ipaddr_and_move (uint8_t *buffer, an_addr_t address)
{
    an_v4addr_t v4addr = AN_V4ADDR_ZERO;
    an_v6addr_t v6addr = AN_V6ADDR_ZERO;
    uint8_t *addr = NULL;
    uint8_t stype = 0;

    if (!buffer) {
        return (NULL);
    }
    
    if (an_addr_is_v4(address)) {
        v4addr = an_addr_v4ton(address); 
        addr = (uint8_t *)&v4addr;
        stype = AN_TLV_STYPE_IPV4_ADDR;
        an_tlv_compose(buffer, AN_TLV_TYPE_IF_IPADDR, stype, 
                       sizeof(v4addr), addr);
    } else {
        v6addr = an_addr_v6ton(address); 
        addr = (uint8_t *)&v6addr;
        stype = AN_TLV_STYPE_IPV6_ADDR;
        an_tlv_compose(buffer, AN_TLV_TYPE_IF_IPADDR, stype, 
                       sizeof(v6addr), addr);
    }
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_if_name_and_move (uint8_t *buffer, uint8_t *if_name)
{
    if (!buffer) {
        return (NULL);
    }
    
    an_tlv_compose(buffer, AN_TLV_TYPE_IF_NAME, 1, 
                   1 + an_strnlen(if_name, 99), if_name);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_device_ipaddr_and_move (uint8_t *buffer, an_addr_t address)
{
    an_v4addr_t v4addr = AN_V4ADDR_ZERO;
    an_v6addr_t v6addr = AN_V6ADDR_ZERO;
    uint8_t *addr = NULL;
    uint8_t stype = 0;

    if (!buffer) {
        return (NULL);
    }
    
    if (an_addr_is_v4(address)) {
        v4addr = an_addr_v4ton(address); 
        addr = (uint8_t *)&v4addr;
        stype = AN_TLV_STYPE_IPV4_ADDR;
        an_tlv_compose(buffer, AN_TLV_TYPE_DEVICE_IPADDR, stype, 
                       sizeof(v4addr), addr);
    } else {
        v6addr = an_addr_v6ton(address); 
        addr = (uint8_t *)&v6addr;
        stype = AN_TLV_STYPE_IPV6_ADDR;
        an_tlv_compose(buffer, AN_TLV_TYPE_DEVICE_IPADDR, stype, 
                       sizeof(v6addr), addr);
    }
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_anra_ipaddr_and_move (uint8_t *buffer, an_addr_t address)
{
    an_v4addr_t v4addr = AN_V4ADDR_ZERO;
    an_v6addr_t v6addr = AN_V6ADDR_ZERO;
    uint8_t *addr = NULL;
    uint8_t stype = 0;

    if (!buffer) {
        return (NULL);
    }
    
    if (an_addr_is_v4(address)) {
        v4addr = an_addr_v4ton(address); 
        addr = (uint8_t *)&v4addr;
        stype = AN_TLV_STYPE_IPV4_ADDR;
        an_tlv_compose(buffer, AN_TLV_TYPE_ANRA_IPADDR, stype, 
                       sizeof(v4addr), addr);
    } else {
        v6addr = an_addr_v6ton(address); 
        addr = (uint8_t *)&v6addr;
        stype = AN_TLV_STYPE_IPV6_ADDR;
        an_tlv_compose(buffer, AN_TLV_TYPE_ANRA_IPADDR, stype, 
                       sizeof(v6addr), addr);
    }
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_anra_sign_and_move (uint8_t *buffer, an_sign_t sign)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!sign.data || !sign.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_TLV_TYPE_ANRA_SIGN, 1, sign.len, sign.data);
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_masa_sign_and_move (uint8_t *buffer, an_sign_t sign)
{
    if (!buffer) {
        return (NULL);
    }

    if (!sign.data || !sign.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_TLV_TYPE_MASA_SIGN, 1, sign.len, sign.data);
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_anra_cert_and_move (uint8_t *buffer, an_cert_t anra_cert)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!anra_cert.data || !anra_cert.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_TLV_TYPE_CERTIFICATE, AN_TLV_STYPE_ANRA_CERT, 
                   anra_cert.len, anra_cert.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_ospf_cfg_and_move (uint8_t *buffer, an_routing_cfg_t routing_info)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!routing_info.ospf_pid) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_TLV_TYPE_ROUTING_CFG, AN_TLV_STYPE_OSPF,
                   sizeof(an_routing_cfg_t), (uint8_t *)&routing_info);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_cert_request_and_move (uint8_t *buffer, an_cert_req_t cert_req)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!cert_req.data || !cert_req.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_TLV_TYPE_CERT_REQ, 1, 
                   cert_req.len, cert_req.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_cert_req_sign_and_move (uint8_t *buffer, an_sign_t cert_req_sign)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!cert_req_sign.data || !cert_req_sign.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_TLV_TYPE_CERT_REQ_SIGN, 1, 
                   cert_req_sign.len, cert_req_sign.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_public_key_and_move (uint8_t *buffer, an_key_t public_key)
{
    if (!buffer) {
        return (NULL);
    }
    
    if (!public_key.data || !public_key.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_TLV_TYPE_PUBLIC_KEY, 1, 
                   public_key.len, public_key.data);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_intent_version_and_move (uint8_t *buffer, an_intent_ver_t version)
{
    an_intent_ver_t version_in_nw_order = 0;

    if (!buffer) {
        return (NULL);
    }
    
    if (!version) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_TLV_TYPE_IDP_VERSION, 1, 
                   sizeof(an_intent_ver_t), (uint8_t *)&version_in_nw_order);

    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_service_info_data_and_move (uint8_t *buffer, 
            an_service_info_t *srvc_info)
{
    an_v4addr_t v4addr = AN_V4ADDR_ZERO;
    an_v6addr_t v6addr = AN_V6ADDR_ZERO;
    uint8_t *addr = NULL;
    uint8_t addr_len = 0;
    uint8_t stype = 0;

    if (!buffer) {
        return (NULL);
    }

    if (srvc_info->srvc_type < AN_SERVICE_AAA || 
        srvc_info->srvc_type >= AN_SERVICE_MAX) {
        an_log(AN_LOG_SRVC,"\n%sInvalid Service type", an_srvc_prefix);
        return (buffer);
    }
    stype = AN_TLV_STYPE_AAA + srvc_info->srvc_type;

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

    an_log(AN_LOG_SRVC,"\n%sComposing tlv for service info stype = %d addr_len = %d", 
            an_srvc_prefix, stype, addr_len); 
    an_tlv_compose(buffer, AN_TLV_TYPE_SERVICE, stype,
              addr_len, addr);
    
    return (an_tlv_get_next_tlv(buffer));
}

uint8_t *
an_tlv_compose_acp_client_data_and_move (uint8_t *buffer, 
            an_payload_t payload)
{

    if (!buffer) {
        return (NULL);
    }

    if (!payload.data || !payload.len) {
        return (buffer);
    }

    an_tlv_compose(buffer, AN_TLV_TYPE_ACP_PAYLOAD, 1,
                   payload.len, payload.data);
    
    return (an_tlv_get_next_tlv(buffer));
}
