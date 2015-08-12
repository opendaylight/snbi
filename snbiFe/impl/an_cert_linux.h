/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#ifndef __AN_CERT_LINUX_H__
#define __AN_CERT_LINUX_H__
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

EVP_PKEY* an_key_get_private_key_from_keypair (uint8_t *key_label);
void an_openssl_init(void);
void an_cert_save(uint8_t *filename, an_cert_t cert);
#endif
