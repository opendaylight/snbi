/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_types.h"
#include "an.h"
#include "an_bs.h"
#include "an_logger.h"
#include "an_key.h"
#include "an_mem.h"
#include "an_event_mgr.h"
#include "an_cert.h"
#include "an_sudi.h"

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
    return;
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
an_cert_gen_certificate_request (int32_t pki_sd, uint8_t *device_name, 
                    uint8_t *domain_name, uint8_t *key_label, 
                    an_cert_req_t *pkcs10, an_sign_t *cert_req_sign)
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
an_cert_generate_request (uint8_t *key_label, uint8_t *device_name, 
            uint8_t *domain_name, an_cert_req_t *pkcs10, an_sign_t *pkcs10_sign)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (AN_CERT_INPUT_PARAM_INVALID);
}

an_cert_api_ret_enum 
an_cert_enroll (an_cert_req_t *pkcs10, an_sign_t pkcs10_sign, 
                an_key_t *public_key, an_cert_t *cert)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (AN_CERT_INPUT_PARAM_INVALID);
}

an_cert_api_ret_enum
an_cert_reset_domain_ca_cert (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_CERT_API_SUCCESS);
}

an_cert_api_ret_enum
an_cert_set_domain_ca_cert (an_cert_t domain_ca_cert)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_CERT_API_SUCCESS);
}

an_cert_api_ret_enum
an_cert_set_domain_device_cert (an_cert_t device_cert)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
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
an_cert_get_cert_expire_time (an_cert_t cert,
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
    return;
}
