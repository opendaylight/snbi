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
#include <an_cert_linux.h>
#include <sys/stat.h>
#include "../al/an_str.h"
#include <unistd.h>

void 
an_openssl_init (void) 
{
    /* ---------------------------------------------------------- *
     * These function calls initialize openssl for correct work.  *
     * ---------------------------------------------------------- */
     OpenSSL_add_all_algorithms();
     ERR_load_BIO_strings();
     ERR_load_crypto_strings();
}

void
an_cert_serial_num_print (const an_cert_t cert)
{
    ASN1_INTEGER *asn1_serial = NULL;
    X509 *x509_cert = d2i_X509(NULL, (const unsigned char **)&cert.data,
                                cert.len);
    BIO *outbio = NULL;
    if (!x509_cert) {
        return;
    }
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!outbio) {
        return;
    }
   /* ---------------------------------------------------------- *
    * Extract the certificate's serial number.                   *
    * ---------------------------------------------------------- */
    asn1_serial = X509_get_serialNumber(x509_cert);
    if (asn1_serial == NULL) {
       printf("Error getting serial number from certificate\n");
    }
    i2a_ASN1_INTEGER(outbio, asn1_serial);
    BIO_puts(outbio,"");
   /* ---------------------------------------------------------- *
     * Free up the resources                                      *
     * ---------------------------------------------------------- */
      X509_free(x509_cert);
      BIO_free_all(outbio);
}

void
an_cert_save (uint8_t *filename, an_cert_t cert)
{
    X509 *x509_cert = d2i_X509(NULL, (const unsigned char **)&cert.data, 
                                cert.len);
    BIO *out = NULL;  

    if (!x509_cert) {
        return;
    }
    out = BIO_new_file(filename, "w+");
    if (!out) {
        return;
    }
    PEM_write_bio_X509(out, x509_cert);
    BIO_free_all(out);
    X509_free(x509_cert);
}

an_cert_api_ret_enum
an_cert_get_subject_name (an_cert_t cert, uint8_t **name, uint16_t *len)
{
    X509_NAME *certsubject = NULL;
    an_cert_api_ret_enum retval = AN_CERT_API_SUCCESS;
    X509 *x509_cert = d2i_X509(NULL, (const unsigned char **)&cert.data, 
                                cert.len);
    
    if (!x509_cert) {
        return AN_CERT_UNKNOWN_FAILURE;
    }

    certsubject = X509_get_subject_name(x509_cert);
    if(!certsubject) {
       retval =  AN_CERT_UNKNOWN_FAILURE;
       goto free_all;
    }
    char *subj = X509_NAME_oneline(certsubject, NULL, 0);
    if (subj) {
        *len = strlen(subj);
        *name = (uint8_t *)an_malloc_guard((*len)+1, NULL);
        if (!*name) {
            return (AN_CERT_MEM_ALLOC_FAIL);
        }
        memcpy(*name, subj, *len);
        name[*len] = '\0';
    } else {
        retval = AN_CERT_UNKNOWN_FAILURE;
    }
    
    /* ---------------------------------------------------------- *
     * Free up the resources                                      *
     * ---------------------------------------------------------- */
    free_all :
        if (x509_cert)
            X509_free(x509_cert);

    return (retval);
}

void 
an_cert_display (const an_cert_t cert)
{
    BIO *outbio = NULL;
    X509 *x509_cert = d2i_X509(NULL, (const unsigned char **)&cert.data, 
                                    cert.len);
    int ret;

    if (!x509_cert) {
        return;
    }
    /* ---------------------------------------------------------- *
     * Create the Input/Output BIO's.                             *
     * ---------------------------------------------------------- */
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!outbio) {
        goto free_all;
    }
    /* ---------------------------------------------------------- *
     * Print the certificate                                      *
     * ---------------------------------------------------------- */
    ret = X509_print_ex(outbio, x509_cert, 0, 0);
    /* ---------------------------------------------------------- *
     * Free up the resources                                      *
     * ---------------------------------------------------------- */
    free_all:
        if (x509_cert)
            X509_free(x509_cert);
        if (outbio)
            BIO_free_all(outbio);
}

//----------------Digital Signature--------------------------
an_cert_api_ret_enum
an_cert_digital_signature(uint8_t *pkcs10_hash_data, uint16_t pkcs10_hash_len, uint8_t **sig, uint *siglen)
{
     int err;
     EVP_PKEY *private_key = NULL;
     EVP_MD_CTX     md_ctx;
     int sig_len = 0;
     unsigned char sig_buf [4096];
     an_cert_api_ret_enum retval = AN_CERT_API_SUCCESS;
     /* Do the signature */
     private_key = an_key_get_private_key_from_keypair(NULL);
     if (!private_key) {
        return (AN_CERT_KEY_GET_PRIKEY_FAIL);
     }
     EVP_SignInit   (&md_ctx, EVP_sha1());
     EVP_SignUpdate (&md_ctx, pkcs10_hash_data, strlen(pkcs10_hash_data));
     sig_len = sizeof(sig_buf);
     err = EVP_SignFinal (&md_ctx, sig_buf, &sig_len, private_key);
     if (err != 1) {
        ERR_print_errors_fp(stderr);
        retval = AN_CERT_KEY_GET_PRIKEY_FAIL;
     }
     if (sig_len != 0) {
        *siglen = sig_len;
        *sig = (uint8_t *)an_malloc_guard((*siglen)+1, NULL);
        if (!*sig) {
            return(AN_CERT_MEM_ALLOC_FAIL);
        }
       strncpy(*sig, sig_buf, *siglen);
     } else {
       retval = AN_CERT_UNKNOWN_FAILURE;
     }

     EVP_PKEY_free (private_key);
     return (retval);
}
an_cert_api_ret_enum
an_encrypt (const char *key_label, uchar *pkcs10_hash_data, 
            uint pkcs10_hash_len,  uint key_num,
            uchar **sig, uint *siglen)
{
    an_cert_api_ret_enum retval = AN_CERT_API_SUCCESS;

    retval = an_cert_digital_signature(pkcs10_hash_data, pkcs10_hash_len, sig, siglen);
    return (retval);
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
    int ret = 0;
    X509_REQ *x509_req = NULL;
    X509_NAME *x509_name = NULL;
    EVP_PKEY *pKey = NULL;
    BIGNUM *bne = NULL;
    an_udi_t my_udi = {};
    an_cert_api_ret_enum retval = AN_CERT_API_SUCCESS;
    ssize_t csr_len;
    unsigned char *bufferIn = NULL;
    unsigned char *bufferIn_sign = NULL;

    if (!device_id || !domain_id || !pkcs10 || !pkcs10_sign) {
        printf("\n Invalid device or domain name");
        return (AN_CERT_INPUT_PARAM_INVALID);
    }
    BIO* keypair_bio = BIO_new_file(PRIVATE_KEY_LOCATION, "r");
    if (!keypair_bio) {
        return (AN_CERT_UNKNOWN_FAILURE);
    }
    RSA* keypair = RSA_new();
    PEM_read_bio_RSAPrivateKey(keypair_bio, &keypair, 0, NULL);

    if (keypair == NULL) {
        retval = AN_CERT_UNKNOWN_FAILURE;
        printf("\n Keypair is NULL");
        goto free_all;
    }

    x509_req = X509_REQ_new();
    if (x509_req == NULL) {
        retval = AN_CERT_UNKNOWN_FAILURE;
        printf("\n Failed to create X509_REQ structure");
        goto free_all;
    }

    // Set the version
    ret = X509_REQ_set_version(x509_req, 2);
    if (ret != 1){
        retval = AN_CERT_UNKNOWN_FAILURE;
        goto free_all;
    }

    // Set the name for x509 request
    x509_name = X509_REQ_get_subject_name(x509_req);
    if (x509_name == NULL) {
       retval = AN_CERT_UNKNOWN_FAILURE;
       printf("\n Failed to create X509_NAME structure");
       goto free_all;
    }

    // Add subject name

    ret = X509_NAME_add_entry_by_txt(x509_name,"name", MBSTRING_ASC, device_id,
                                     -1, -1, 0);
    if (ret != 1){
        retval = AN_CERT_UNKNOWN_FAILURE;
        goto free_all;
    }

    ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, device_id, 
                                    -1, -1, 0);
    if (ret != 1){
        retval = AN_CERT_UNKNOWN_FAILURE;
        goto free_all;
    }

    ret = X509_NAME_add_entry_by_txt(x509_name,"OU", MBSTRING_ASC, domain_id,
                                     -1, -1, 0);
    if (ret != 1){
        retval = AN_CERT_UNKNOWN_FAILURE;
        goto free_all;
    }
    an_get_udi(&my_udi);
    ret = X509_NAME_add_entry_by_txt(x509_name,"serialNumber", MBSTRING_ASC, 
                                    my_udi.data, -1, -1, 0);
    if (ret != 1){
        retval = AN_CERT_UNKNOWN_FAILURE;
        goto free_all;
    }

    // set public key of x509 req
    pKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pKey, keypair);

    keypair = NULL;   // will be free rsa when EVP_PKEY_free(pKey)

    ret = X509_REQ_set_pubkey(x509_req, pKey);
    if (ret != 1){
        retval = AN_CERT_KEY_GET_PUBKEY_FAIL;
        goto free_all;
    }
    csr_len = (ssize_t)i2d_X509_REQ(x509_req, NULL);
    pkcs10->len = csr_len;
    pkcs10->data = (uint8_t *)an_malloc_guard(pkcs10->len, "AN Cert Req PKCS");
    if (!pkcs10->data) {
        retval = AN_CERT_MEM_ALLOC_FAIL;
        goto free_all;
    }

    bufferIn = pkcs10->data;
    i2d_X509_REQ(x509_req, &bufferIn);

    // set sign key of x509 req
    ret = X509_REQ_sign(x509_req, pKey, EVP_sha1());    // return x509_req->signature->length
    if (ret <= 0){
        retval = AN_CERT_REQUEST_GENERATION_FAIL;
        goto free_all;
    }
    csr_len = (ssize_t)i2d_X509_REQ(x509_req, NULL);
    pkcs10_sign->len = csr_len ;
    pkcs10_sign->data = (char*)an_malloc_guard(csr_len, NULL);
    if (!pkcs10_sign->data) {
        retval = AN_CERT_MEM_ALLOC_FAIL;
        goto free_all;
    }
    bufferIn_sign = pkcs10_sign->data;
    i2d_X509_REQ(x509_req, &bufferIn_sign);

    //free
    free_all:
        if (x509_req)
            X509_REQ_free(x509_req);
        if (pKey)
            EVP_PKEY_free(pKey);
        if (bne)
            BN_free(bne);
        if (keypair_bio)
             BIO_free(keypair_bio);
    return (retval);
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
    an_cert_save (CA_CERT_LOCATION, domain_ca_cert);
    return (AN_CERT_API_SUCCESS);
}

an_cert_api_ret_enum
an_cert_set_domain_device_cert (uint8_t *tp_label, an_cert_t device_cert)
{
    an_cert_save (DEVICE_CERT_LOCATION, device_cert);
    return (AN_CERT_API_SUCCESS);
}

boolean
an_cert_is_device_cert_valid (an_cert_t *cert)
{
    int status_bf, status_af;
    an_cert_t an_cert;
    X509 *x509_cert = NULL;

    an_cert.data = cert->data;
    an_cert.len = cert->len;
    x509_cert = d2i_X509(NULL, (const unsigned char **)&an_cert.data,
                                an_cert.len);
    
    if(!x509_cert) {
        return (FALSE);
    }

    status_bf = X509_cmp_current_time(X509_get_notBefore(x509_cert));
    status_af = X509_cmp_current_time(X509_get_notAfter(x509_cert));
    if(status_bf < 0 && status_af > 0) {
        X509_free(x509_cert);
        return (TRUE);
    } else {
        X509_free(x509_cert);
        return (FALSE);
    }
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
//printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
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
an_cert_get_subject_cn (an_cert_t cert, uint8_t **subject_cn, uint16_t *len)
{
    X509_NAME *certsubject = NULL;
    X509 *x509_cert = d2i_X509(NULL, (const unsigned char **)&cert.data, 
                                cert.len);
    char subject_cn_val[256] = "n/a";
    an_cert_api_ret_enum retval = AN_CERT_API_SUCCESS;
    
    if(!x509_cert) {
        return AN_CERT_UNKNOWN_FAILURE;
    }

    certsubject = X509_get_subject_name(x509_cert);

    if (!certsubject) {
        retval =  AN_CERT_UNKNOWN_FAILURE;
        goto free_all;
    }

    X509_NAME_get_text_by_NID(certsubject, NID_commonName,
                                    subject_cn_val, 256);
    *len = strlen(subject_cn_val);
    *subject_cn = (uint8_t *)an_malloc_guard((*len)+1, NULL);
    if (!*subject_cn) {
        return (AN_CERT_MEM_ALLOC_FAIL);
    }
    memcpy(*subject_cn, subject_cn_val, (*len)+1);
    /* ---------------------------------------------------------- *
    * Free up the resources                                      *
    * ---------------------------------------------------------- */
    free_all :
        if (x509_cert)
            X509_free(x509_cert);

    return (retval);
}

an_cert_api_ret_enum
an_cert_get_subject_ou (an_cert_t cert, uint8_t **subject_ou, uint16_t *len)
{
    X509_NAME *certsubject = NULL;
    X509 *x509_cert = d2i_X509(NULL, (const unsigned char **)&cert.data, 
                            cert.len);
    char subject_ou_val[256] = "n/a";
    an_cert_api_ret_enum retval = AN_CERT_API_SUCCESS;

    if(!x509_cert) {
        return AN_CERT_UNKNOWN_FAILURE;
    }

    certsubject = X509_get_subject_name(x509_cert);
    if (!certsubject) {
        retval =  AN_CERT_UNKNOWN_FAILURE;
        goto free_all;
    }

    X509_NAME_get_text_by_NID(certsubject, NID_organizationalUnitName,
                                    subject_ou_val, 256);
    *len = an_strlen(subject_ou_val);
    *subject_ou = (uint8_t *)an_malloc_guard((*len)+1, NULL);
    if (!*subject_ou) {
        return (AN_CERT_MEM_ALLOC_FAIL);
    }
    memcpy(*subject_ou, subject_ou_val, (*len)+1);
    /* ---------------------------------------------------------- *
    * Free up the resources                                      *
    * ---------------------------------------------------------- */
    free_all :
        if (x509_cert)
            X509_free(x509_cert);

    return (retval);
}

an_cert_api_ret_enum
an_cert_get_subject_sn (an_cert_t cert, uint8_t **serialnum, uint16_t *len)
{
    X509_NAME *certsubject = NULL;
    X509 *x509_cert = d2i_X509(NULL, (const unsigned char **)&cert.data, 
                            cert.len);
    char subject_serialNumber[256] = "n/a";
    an_cert_api_ret_enum retval = AN_CERT_API_SUCCESS;

    if (!x509_cert) {
        return AN_CERT_UNKNOWN_FAILURE;
    }

    certsubject = X509_get_subject_name(x509_cert);
    if (!certsubject) {
        retval =  AN_CERT_UNKNOWN_FAILURE;
        goto free_all;
    }
    X509_NAME_get_text_by_NID(certsubject, NID_serialNumber,
                                 subject_serialNumber, 256);
    *len = strlen(subject_serialNumber);
    *serialnum = (uint8_t *)an_malloc_guard((*len)+1, NULL);
    if (!*serialnum) {
        return (AN_CERT_MEM_ALLOC_FAIL);
    }
    memcpy(*serialnum, subject_serialNumber, (*len)+1);
    /* ---------------------------------------------------------- *
    * Free up the resources                                      *
    * ---------------------------------------------------------- */
    free_all :
        if (x509_cert)
            X509_free(x509_cert);

    return (retval);
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

