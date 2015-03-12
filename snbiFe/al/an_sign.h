/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_SIGN_H__
#define __AN_SIGN_H__

#include "an_types.h"

typedef enum an_sign_digest_type_e_ {
    AN_SIGN_DIGEST_NONE = 0,
    AN_SIGN_DIGEST_AUTO,
    AN_SIGN_DIGEST_MD5,
    AN_SIGN_DIGEST_SHA1,
    AN_SIGN_DIGEST_SHA256,
    AN_SIGN_DIGEST_SHA384,
    AN_SIGN_DIGEST_SHA512,
} an_sign_digest_type_e;
    
typedef enum an_sign_api_ret_enum_ {
    AN_SIGN_API_SUCCESS,
	AN_SIGN_API_FAIL,
    
    AN_SIGN_INPUT_PARAM_INVALID,
    AN_SIGN_PKI_SES_START_FAIL, 
    AN_SIGN_MEM_ALLOC_FAIL,

    AN_SIGN_INPUT_DATA_FAIL,
	AN_SIGN_KEYPAIR_FETCH_FAIL,
    AN_SIGN_VERIFY_FAIL,

    AN_SIGN_ENUM_MAX,
     
} an_sign_api_ret_enum;

typedef struct an_sign_t_ {
    uint8_t *data;
    uint16_t len;
} an_sign_t;

an_sign_api_ret_enum
an_sign_data(uint8_t *data, uint16_t data_len, an_sign_digest_type_e digest_type,
              an_sign_t *sign, uint8_t *tp_label, uint8_t *key_label);
an_sign_api_ret_enum
an_sign_verify_using_key(uint8_t *key_label, uint8_t *data, uint16_t data_len,
						 uint8_t *sign, uint16_t sign_len);
an_sign_api_ret_enum
an_verify_signature(uint8_t *data, uint16_t data_len, an_sign_digest_type_e digest_type,
                    an_cert_t cert, an_sign_t sign);
an_sign_api_ret_enum
an_sign_gen_hash(uint8_t *in_data, uint32_t in_data_len, uint8_t *hash);

boolean an_smime_sign_message(uint8_t *data, uint16_t data_len,
                an_sign_t *sign, uint8_t *label);

boolean an_smime_reply_verify_and_extract(uint8_t* pkcs7_data, uint8_t* pki_label,
                uint8_t **data_extract, uint32_t *data_len);
extern const uint8_t *an_sign_enum_get_string(an_sign_api_ret_enum enum_type);

#endif
