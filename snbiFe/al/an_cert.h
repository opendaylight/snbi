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

#define AN_REVOKE_CHECK_TIMER_INTERVAL 6 * 60 * 60 * 1000 //This is 6 hour in msec
#define AN_CERT_100th_POLL_COUNT 5
#define AN_CERT_LIFETIME_75_PERC 75
#define AN_CERT_LIFETIME_76_PERC 76
#define AN_CERT_LIFETIME_80_PERC 80
#define AN_CERT_LIFETIME_40_PERC 40
#define AN_CERT_BEFORE_EXPIRY_IMPORT_MAX_WAIT_TIME 24 * 60 * 60 * 1000 //1 day
#define AN_CERT_AFTER_EXPIRY_IMPORT_MAX_WAIT_TIME 5 * 60 * 1000 //5 mins

#define AN_CERT_EXPIRY_IMPORT_MIN_WAIT_TIME 3 * 60 * 1000 //3 mins
#define AN_CERT_MIN_WAIT_TIME_TO_CRL_VALIDATE 10 * 60 //10 mins
#define AN_CERT_CRL_PREPUBLISH_INTERVAL 3 //3 mins before crl expiry
#define AN_CERT_ANRA_CRL_PREPUBLISH_INTERVAL 6 //3 mins before crl expiry
#define AN_CERT_CRL_RETRY_INTERVAL 15 //15min - Min value is 15 mins ONLY
#define AN_CERT_WAIT_TO_RERUN_REVOKE_CHECK 3 * 60 * 1000 //3 mins

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
    AN_CERT_AUTH_ENROLL_TP_NOT_EXIST, 
    AN_CERT_LOCAL_CA_NOT_EXIST, 
    AN_CERT_TP_CA_CERT_NULL,
    AN_CERT_RESET_TP_FAIL,
    AN_CERT_CRYPTO_PKI_SES_HNDL_INVALID,
    AN_CERT_CRYPTO_GET_TP_FROM_LABEL_INVALID,
    AN_CERT_INPUT_PARAM_INVALID,
    AN_CERT_EXTERNAL_CA_NOT_EXIST, 
    AN_CERT_NO_DEVICE_CERT_IN_TP,
    AN_CERT_GET_ANR_IP_FAIL,
    AN_CERT_EXPIRED_DEVICE_CERT_IN_TP,
    AN_CERT_BUSY_IN_RENEWAL,
    AN_CERT_OPER_NOT_SUPPORTED,
    AN_CERT_CONVERSION_FAIL,
    AN_CERT_REQUEST_GENERATION_FAIL,
    AN_CERT_KEY_GET_USAGE_FAIL,
    AN_CERT_KEY_GET_PUBKEY_FAIL,
    AN_CERT_KEY_GET_PRIKEY_FAIL,
    AN_CERT_KEY_USAGE_TYPE_NOT_SUPPORTED,

    AN_CERT_UNKNOWN_FAILURE,

    AN_CERT_ENUM_MAX,
    
} an_cert_api_ret_enum;

typedef enum an_cert_csr_type_e_ {
	AN_CERT_CSR_NONE,
	AN_CERT_CSR_HASH,
	AN_CERT_CSR_DER,
	AN_CERT_CSR_MAX,
} an_cert_csr_type_e;

void an_cert_display(const an_cert_t cert);
void an_cert_short_display(const an_cert_t cert, const an_log_type log_type);
typedef enum an_cert_type_enum_e_ {
    AN_CERT_TYPE_BOOTSTRAPPED,
    AN_CERT_TYPE_RENEWED,
    AN_CERT_TYPE_EMPTY,

} an_cert_type_enum;

void an_certificate_display(const an_cert_t cert, const an_log_type_e log_type);
void an_cert_short_print(const an_cert_t cert);
void an_cert_serial_num_print(const an_cert_t cert);
int32_t an_cert_compare(const an_cert_t cert1, const an_cert_t cert2);
boolean an_cert_equal(const an_cert_t cert1, const an_cert_t cert2);
boolean an_cert_get_udi(const an_cert_t cert, an_udi_t *udi);
an_cert_api_ret_enum 
an_cert_get_subject_name(an_cert_t cert, uint8_t **subject, uint16_t *len);
an_cert_api_ret_enum 
an_cert_get_subject_cn(an_cert_t cert, uint8_t **subject_cn, uint16_t *len);
an_cert_api_ret_enum 
an_cert_get_subject_ou(an_cert_t cert, uint8_t **subject_ou, uint16_t *len);
an_cert_api_ret_enum
an_cert_get_subject_sn(an_cert_t cert, uint8_t **serialnum, uint16_t *len);

an_cert_api_ret_enum 
an_cert_get_issuer_name(an_cert_t cert, uint8_t **issuer, uint16_t *len);
an_cert_api_ret_enum 
an_cert_get_serial_num(an_cert_t cert, uint8_t **name, uint16_t *len);

an_cert_api_ret_enum an_crypto_cert_get_public_key(an_cert_t *cert, an_key_t *public_key);
an_cert_api_ret_enum an_crypto_cert_get_validity_period(an_cert_t *cert,
										uint32_t *start, uint32_t *end); 
an_cert_api_ret_enum an_cert_enroll_response_msg_cb(an_enroll_msg_t *msg);
an_cert_api_ret_enum 
an_cert_gen_certificate_request(int32_t pki_sd, an_mac_addr *mac_address, uint8_t *device_id, 
             uint8_t *domain_id, uint8_t *key_label, an_cert_req_t *cert_req, 
             an_sign_t *cert_req_sign, int8_t csr_type);
an_cert_api_ret_enum an_cert_grant_certificate_blocking(int32_t pki_sd, 
             an_sign_t cert_req_sign, an_cert_t *cert, int type, uint8_t *inner_der_data, uint16_t innder_der_len);
boolean
an_cert_grant_certificate_proxy(int32_t pki_sd, uint8_t *key_label, 
                            an_cert_req_t cert_req, an_cert_t *cert);

an_cert_api_ret_enum
an_cert_generate_request(uint8_t *tp_label, uint8_t *key_label, 
						 an_mac_addr *mac_address, uint8_t *device_id, 
                         uint8_t *domain_id, an_cert_req_t *pkcs10, 
                         an_sign_t *pkcs10_sign);
an_cert_api_ret_enum
an_cert_enroll(an_cert_req_t *pkcs10, an_sign_t *pkcs10_sign, an_cert_req_t *signed_pkcs10,
			   an_key_t *public_key, an_cert_t *cert, an_udi_t device_udi, 
			   an_addr_t proxy_device, an_iptable_t iptable);

an_cert_api_ret_enum an_cert_set_domain_ca_cert(uint8_t *tp_label, an_cert_t domain_ca_cert);
an_cert_api_ret_enum an_cert_reset_domain_ca_cert(uint8_t *tp_label);
an_cert_api_ret_enum an_cert_set_domain_device_cert(uint8_t *tp_label, an_cert_t device_cert);
an_cert_api_ret_enum  
an_cert_get_device_cert_from_tp(uint8_t *tp_label, an_cert_t *cert);
an_cert_api_ret_enum 
an_cert_get_ca_cert_from_tp(uint8_t *tp_label, an_cert_t *cert);

an_cert_validation_result_e 
an_cert_validate_override_revoke_check(an_cert_t *peer_cert, 
                                    const an_log_type_e log_type);

an_cert_validation_result_e 
an_cert_validate_with_revoke_check(an_cert_t *peer_cert, void *ctx);

boolean an_create_trustpoint (uint8_t* label, uint8_t* filename);
boolean an_tp_exists(uint8_t *label);
an_cert_api_ret_enum an_crypto_convert_der_to_printable(an_buffer_t *item, uint8_t **string);
an_cert_api_ret_enum an_crypto_convert_b64_to_der_inplace(an_buffer_t *b64in, uint16_t *out_len);

an_cert_api_ret_enum an_cert_update_trustpoint (an_addr_t enrol_ip, 
                    boolean ra_mode_server);
an_cert_api_ret_enum an_cert_config_trustpoint (an_addr_t enrol_ip);
an_cert_api_ret_enum an_cert_get_cert_expire_time(an_cert_t* cert, 
                 an_unix_msec_time_t *validity_interval, 
                 an_unix_time_t *validity_time);
boolean an_cert_check_if_not_expired(an_cert_t *cert);
boolean an_cert_is_device_cert_valid(an_cert_t *cert);
void an_cert_set_auto_enroll_perc(int auto_enroll_perc);
uint16_t an_cert_get_auto_enroll_perc(void);
void an_cert_displaycert_in_pem(uchar *cert_der, uint16_t cert_len);
void an_cert_pki_crl_cleanup(void);
void an_cert_compute_cert_lifetime_percent(an_unix_msec_time_t cert_validity_interval, 
                    an_unix_time_t *perc_5, an_unix_time_t *perc_1, 
                    an_unix_time_t *perc_40,
                    an_unix_msec_time_t *perc_75);
an_cert_api_ret_enum
an_cert_get_crl_expiry_time(an_cert_t* cert,
                            an_unix_time_t *crl_expire_time);
boolean an_cert_is_tp_busy_in_renew(void);
void an_cert_config_crl_auto_download(uint16_t interval);
void an_cert_unconfig_crl_auto_download(void);
boolean an_cert_is_crl_present(an_cert_t *cert);
const uint8_t *an_cert_enum_get_string(an_cert_api_ret_enum enum_type);
boolean 
an_cert_validate_subject_cn(an_cert_t cert, uint8_t *device_id);
boolean 
an_cert_validate_subject_ou(an_cert_t cert, uint8_t *domain_id);
boolean 
an_cert_validate_subject_sn(an_cert_t cert, uint8_t *sn_string, 
                            uint16_t sn_length);
void an_cert_cleanup(void);
#endif
