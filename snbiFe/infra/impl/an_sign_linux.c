/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_sign.h>
#include <an_sudi.h>
#include <an_logger.h>
#include <an_mem.h>
#include <an_tlv.h>
#include <an_http_linux.h>

#define AN_SHA1_LENGTH 20
uint16_t an_sha1_length = AN_SHA1_LENGTH + 1;  

const uint8_t *an_sign_debug_enum_string [] = {
    "AN signature API success",
    "input params are invalid",
    "failed to start the PKI session",
    "memory allocation failed",
    "failed to sign the AN message",
    "failed to verify the AN signature",
    "AN sign enum max",
};

const uint8_t *an_sign_enum_get_string (an_sign_api_ret_enum enum_type)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (an_sign_debug_enum_string[enum_type]);
}

an_sign_api_ret_enum
an_sign_data(uint8_t *data, uint16_t data_len, an_sign_digest_type_e digest_type,
              an_sign_t *sign, uint8_t *tp_label, uint8_t *key_label)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_SIGN_API_SUCCESS);
}

an_sign_api_ret_enum
an_verify_signature (uint8_t *data, uint16_t data_len_in, an_sign_digest_type_e digest_type,
                     an_cert_t cert, an_sign_t sign)
{   
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (AN_SIGN_API_SUCCESS);
}

/*
 * Sign the MASA request in the required SMIME format
 */
boolean an_smime_sign_message (uint8_t *data, uint16_t data_len,
        an_sign_t *sign, uint8_t *label)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (TRUE);
}

/*
 * Extract the data from the PKCS7 signature
 */

boolean an_smime_reply_verify_and_extract (uint8_t* pkcs7_data, uint8_t* pki_label,
        uint8_t **data_extract, uint32_t *data_len)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

an_sign_api_ret_enum
an_sign_gen_hash (uint8_t *in_data, uint32_t in_data_len, uint8_t *hash)
{
	#if 0
    SHA1_CTX ctx;

    SHA1Init(&ctx);
    SHA1Update(&ctx, in_data, in_data_len);
    SHA1Final(hash, &ctx);
    DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_INFO, NULL,
                 "\n%sANR IP hash calculated", an_srvc_event);

    hash[an_sha1_length-1] = '\0';
	#endif
     //SINDHU TO-DO
    return (AN_SIGN_API_SUCCESS);
}

