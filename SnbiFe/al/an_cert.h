/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_CERT_H__
#define __AN_CERT_H__

#include "an_types.h"
#include "../al/an_logger.h"
#include "../al/an_sign.h"

typedef enum an_cert_validation_result_e_ {
    AN_CERT_VALIDITY_UNKNOWN = 0,
    AN_CERT_VALIDITY_PASSED,
    AN_CERT_VALIDITY_FAILED,
    AN_CERT_VALIDITY_EXPIRED,
} an_cert_validation_result_e;

typedef enum an_cert_revocation_e_ {
   AN_CERT_REVOCATION_UNKNOWN = 0,
   AN_CERT_REVOCATION_VALID,
   AN_CERT_REVOCATION_INVALID,
} an_cert_revocation_e;

typedef enum an_cert_life_e_ {
    AN_CERT_LIFE_UNKNOWN = 0,
    AN_CERT_LIFE_VALID,
    AN_CERT_LIFE_EXPIRED,
} an_cert_life_e;

typedef struct an_cert_validation_t_ {
    boolean common_trust_anchor;
    an_cert_validation_result_e result;
    an_cert_revocation_e revocation_status;
    an_cert_life_e life;
} an_cert_validation_t;

typedef enum an_cert_api_ret_enum_e_ {
    AN_CERT_API_SUCCESS,
   
    AN_CERT_MEM_ALLOC_FAIL,
    AN_CERT_PKI_SES_START_FAIL,
    AN_CERT_GET_CERT_ATTR_FAIL,
    AN_CERT_SIGN_CERT_REQ_PRIVKEY_FAIL,
    AN_CERT_ENROLL_SUCCESS, 
    AN_CERT_ENROLL_NBCOMPLETE,
    AN_CERT_ENROLL_ERROR,
    AN_CERT_ENROLL_GRANT_FAIL,
    AN_CERT_SET_TP_ENROLL_FAIL,
    AN_CERT_GEN_CERT_SIGN_REQ_FAIL,
    AN_CERT_IMPORT_CA_CERT_FAIL,
    AN_CERT_IMPORT_DEVICE_CERT_FAIL,
    AN_CERT_LOCAL_CA_NOT_EXIST, 
    AN_CERT_RESET_TP_FAIL,
    AN_CERT_CRYPTO_PKI_SES_HNDL_INVALID,
    AN_CERT_CRYPTO_GET_TP_FROM_LABEL_INVALID,
    AN_CERT_INPUT_PARAM_INVALID,

    AN_CERT_ENUM_MAX,
    
} an_cert_api_ret_enum;

void an_cert_display(const an_cert_t cert);
void an_cert_short_display(const an_cert_t cert, const an_log_type log_type);
void an_certificate_display(const an_cert_t cert, const an_log_type_e log_type);
void an_cert_short_print(const an_cert_t cert);
boolean an_cert_get_udi(const an_cert_t cert, an_udi_t *udi);
an_cert_api_ret_enum an_cert_get_subject_name(an_cert_t cert, uint8_t **subject, uint16_t *len);
an_cert_api_ret_enum an_cert_get_subject_cn(an_cert_t cert, uint8_t **cn, uint16_t *len);
boolean an_cert_enroll_msg_cb(an_enroll_msg_t *msg);
an_cert_api_ret_enum an_cert_gen_certificate_request(int32_t pki_sd, uint8_t *device_id, uint8_t *domain_id, 
             uint8_t *key_label, an_cert_req_t *cert_req, an_sign_t *cert_req_sign);
an_cert_api_ret_enum an_cert_grant_certificate (int32_t pki_sd, 
             an_sign_t cert_req_sign, an_cert_t *cert);
boolean
an_cert_grant_certificate_proxy (int32_t pki_sd, uint8_t *key_label, an_cert_req_t cert_req, an_cert_t *cert);

an_cert_api_ret_enum
an_cert_generate_request(uint8_t *key_label, uint8_t *device_id, 
                         uint8_t *domain_id, an_cert_req_t *pkcs10, 
                         an_sign_t *pkcs10_sign);
an_cert_api_ret_enum
an_cert_enroll(an_cert_req_t *pkcs10, an_sign_t pkcs10_sign, an_key_t *public_key, an_cert_t *cert);

an_cert_api_ret_enum an_cert_set_domain_ca_cert(an_cert_t domain_ca_cert);
an_cert_api_ret_enum an_cert_reset_domain_ca_cert(void);
an_cert_api_ret_enum an_cert_set_domain_device_cert(an_cert_t device_cert);
an_cert_api_ret_enum  an_cert_get_device_cert_from_tp(uint8_t *tp_label, an_cert_t *cert);
an_cert_api_ret_enum an_cert_get_ca_cert_from_tp(uint8_t *tp_label, an_cert_t *cert);
an_cert_validation_result_e an_cert_validate(an_cert_t *peer_cert);
boolean an_create_trustpoint (uint8_t* label, uint8_t* filename);
boolean an_tp_exists(uint8_t *label);
#endif
