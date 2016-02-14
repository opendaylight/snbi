/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <an_logger.h>
#include <an_types.h>
#include <an_key.h>
#include <an_mem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

boolean
an_key_generate_keypair (uint8_t *key_label)
{
    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;
    BIO *bp_public = NULL, *bp_private = NULL;
    unsigned long e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, AN_RSA_KEY_MODULUS, bne, NULL);
    if(ret != 1){
        goto free_all;
    }

    // 2. save public key
    bp_public = BIO_new_file(PUBLIC_KEY_LOCATION, "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if(ret != 1){
        goto free_all;
    }

    // 3. save private key
    bp_private = BIO_new_file(PRIVATE_KEY_LOCATION, "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

    // 4. free
    free_all:
        BIO_free_all(bp_public);
        BIO_free_all(bp_private);
        RSA_free(r);
        BN_free(bne);

    return (ret == 1);
}

boolean
an_key_get_public_key (uint8_t *key_label, an_key_t *key)
{
    const char cert_filestr[] = PUBLIC_KEY_LOCATION;
    BIO  *outbio = NULL;
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    int ret;
    char *pub_key = NULL;
    size_t pub_len;

    BIO* rsa_pub_bio = BIO_new_file(cert_filestr, "r");
    RSA* rsa_pub = RSA_new();

    ret = (PEM_read_bio_RSAPublicKey(rsa_pub_bio, &rsa_pub, NULL, NULL)!= NULL);
    if (ret == 0) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                "\n%sFailed to read public key from key pair",an_bs_event);
        return FALSE;
    }
    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, rsa_pub);
    pub_key = (char*)malloc(BN_num_bits(rsa_pub->n) + 1);
    pub_len = BN_num_bits(rsa_pub->n);
    BIO_read(pub, pub_key, pub_len);
    pub_key[pub_len] = '\0';
    key->data = pub_key;
    key->len = pub_len;
    BIO_free(rsa_pub_bio);
    return TRUE;
}

//----------------START Get Private key--------------------------
EVP_PKEY*
an_key_get_private_key_from_keypair (uint8_t *key_label)
{
    const char cert_filestr[] = PRIVATE_KEY_LOCATION;
    EVP_PKEY *pkey;

    BIO* rsa_pub_bio = BIO_new_file(cert_filestr, "r");
    pkey = PEM_read_bio_PrivateKey(rsa_pub_bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                "\n%sFailed to read private key from key pair",an_bs_event);
        return FALSE;
    }
    fprintf(stdout, "RSA Private Key: (%d bit)\n", EVP_PKEY_bits(pkey));

    BIO_free(rsa_pub_bio);
    return(pkey);
}
//----------------END Get Private key--------------------------

boolean
an_key_remove_keypair (uint8_t *key_label)
{
    return (TRUE);
}

