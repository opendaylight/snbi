/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an.h>
#include <an_bs.h>
#include <an_logger.h>
#include <an_key.h>
#include <an_mem.h>
#include <an_event_mgr.h>
#include <an_cert.h>
#include <an_sudi.h>

//void an_cert_display(const an_cert_t cert);
//void an_cert_short_print(const an_cert_t cert);


an_cert_api_ret_enum 
an_cert_get_subject_cn (an_cert_t cert, uint8_t **subject, uint16_t *len)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (AN_CERT_INPUT_PARAM_INVALID);
}

an_cert_api_ret_enum
an_cert_get_subject_name (an_cert_t cert, uint8_t **name, uint16_t *len)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (AN_CERT_INPUT_PARAM_INVALID);
}

void an_cert_display (const an_cert_t cert)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
}

an_cert_api_ret_enum
an_encrypt (const char *key_label, uchar *pkcs10_hash_data, 
            uint pkcs10_hash_len,  uint key_num,
            uchar **sig, uint *siglen)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_CERT_API_SUCCESS);
}

an_cert_api_ret_enum 
an_cert_gen_certificate_request(int32_t pki_sd, an_mac_addr *mac_address, uint8_t *device_id,
             uint8_t *domain_id, uint8_t *key_label, an_cert_req_t *cert_req,
             an_sign_t *cert_req_sign, int8_t csr_type)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (FALSE);
}

void
an_cert_verify_cb (void *ctx, uint status, uint cert_status)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_cert_fetch_cb (void *ctx,  ushort command, ushort status, uchar* rsp)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

boolean
an_cert_enroll_msg_cb (an_enroll_msg_t *msg)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

an_cert_api_ret_enum
an_cert_grant_certificate (int32_t pki_sd, an_sign_t cert_req_sign, an_cert_t *cert)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
                return (AN_CERT_MEM_ALLOC_FAIL);
}

boolean
an_cert_grant_certificate_proxy (int32_t pki_sd, uint8_t *key_label, an_cert_req_t cert_req, an_cert_t *cert)
{ 
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

an_cert_api_ret_enum
an_cert_generate_request(uint8_t *tp_label, uint8_t *key_label,
                         an_mac_addr *mac_address, uint8_t *device_id,
                         uint8_t *domain_id, an_cert_req_t *pkcs10,
                         an_sign_t *pkcs10_sign)

{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (AN_CERT_INPUT_PARAM_INVALID);
}

an_cert_api_ret_enum 
an_cert_enroll(an_cert_req_t *pkcs10, an_sign_t *pkcs10_sign, an_cert_req_t *signed_pkcs10,
               an_key_t *public_key, an_cert_t *cert, an_udi_t device_udi,
               an_addr_t proxy_device, an_iptable_t iptable)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (AN_CERT_INPUT_PARAM_INVALID);
}

an_cert_api_ret_enum
an_cert_reset_domain_ca_cert (uint8_t *tp_label)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_CERT_API_SUCCESS);
}

an_cert_api_ret_enum
an_cert_set_domain_ca_cert (uint8_t *tp_label, an_cert_t domain_ca_cert)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_CERT_API_SUCCESS);
}

an_cert_api_ret_enum
an_cert_set_domain_device_cert (uint8_t *tp_label, an_cert_t device_cert)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_CERT_API_SUCCESS);
}

boolean
an_cert_is_device_cert_valid (an_cert_t *cert)
{
            return (AN_CERT_API_SUCCESS);
}


/* Returns a pointer to the cert data. User need not free it. */
an_cert_api_ret_enum
an_cert_get_device_cert_from_tp (uint8_t *tp_label, an_cert_t *cert)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_CERT_API_SUCCESS);
}

an_cert_api_ret_enum 
an_cert_get_ca_cert_from_tp (uint8_t *tp_label, an_cert_t *cert)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_CERT_API_SUCCESS);
}

boolean
an_tp_exists (uint8_t *cs_label)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}

an_cert_validation_result_e 
an_cert_validate (an_cert_t *peer_cert)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return(AN_CERT_VALIDITY_UNKNOWN);
}

/*
 * Create PKI trustpoint based on label and file
 */

boolean an_create_trustpoint (uint8_t* label, uint8_t* filename)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

an_cert_api_ret_enum 
an_cert_get_cert_expire_time (an_cert_t *cert,
                 an_unix_msec_time_t* validity_interval,
                 an_unix_time_t *validity_time) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return 0;
}

void 
an_cert_displaycert_in_pem (uchar *cert_der, uint16_t cert_len) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

an_cert_api_ret_enum 
an_cert_config_cert_renewal_on_trustpoint (void) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_CERT_UNKNOWN_FAILURE);
}

an_cert_api_ret_enum
an_cert_update_trustpoint (an_addr_t enrol_ip, boolean ra_mode_server)
{
            return (AN_CERT_UNKNOWN_FAILURE);
}

an_cert_api_ret_enum
an_cert_config_trustpoint (an_addr_t enrol_ip)
{
            return (AN_CERT_API_SUCCESS);
}

an_cert_validation_result_e
an_cert_validate_override_revoke_check (an_cert_t *peer_cert,
                                             const an_log_type_e log_type)
{
            return (AN_CERT_VALIDITY_UNKNOWN);
}

void
an_cert_unconfig_crl_auto_download (void)
{
            return;
}

an_cert_api_ret_enum
an_cert_get_subject_ou (an_cert_t cert, uint8_t **subject_ou, uint16_t *len)
{
            return (AN_CERT_API_SUCCESS);
}

an_cert_api_ret_enum
an_cert_get_subject_sn (an_cert_t cert, uint8_t **serialnum, uint16_t *len)
{
            return (AN_CERT_API_SUCCESS);
}

uint16_t
an_cert_get_auto_enroll_perc (void)
{
    return (FALSE);
}

void
an_cert_compute_cert_lifetime_percent (an_unix_msec_time_t cert_validity_interval,
                            an_unix_time_t *perc_5, an_unix_time_t *perc_1,
                            an_unix_time_t *perc_40,
                            an_unix_msec_time_t *perc_75)
{
        return;
}

an_cert_api_ret_enum
an_cert_get_crl_expiry_time (an_cert_t *cert,
                             an_unix_time_t *crl_expire_time)
{
        return (AN_CERT_INPUT_PARAM_INVALID);
}

void
an_cert_config_crl_auto_download (uint16_t interval)
{
        return;
}

boolean
an_cert_is_tp_busy_in_renew (void)
{
        return FALSE;
}

boolean
an_cert_is_crl_present (an_cert_t *cert)
{
        return FALSE;
}

an_cert_validation_result_e
an_cert_validate_with_revoke_check (an_cert_t *peer_cert, void *device_ctx)
{
        return (AN_CERT_VALIDITY_UNKNOWN);
}

