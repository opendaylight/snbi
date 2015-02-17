/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_SUDI_H__
#define __AN_SUDI_H__

#include "an_types.h"

extern uint8_t check_count;
extern boolean udi_available;
extern boolean an_sudi_available;
extern boolean an_sudi_initialized;
extern an_timer an_sudi_check_timer;
void an_sudi_init(void);
void an_sudi_uninit(void);
void an_sudi_check(void);
void an_sudi_clear(void);
uint8_t *an_sudi_get_label(void);
boolean an_sudi_is_available(void);
boolean an_sudi_get_cert(an_cert_t *sudi);
boolean an_sudi_get_udi(an_udi_t *udi);
boolean an_sudi_get_keypair_label(uint8_t **keypair_label);
boolean an_sudi_get_public_key(an_key_t *public_key);
boolean an_sudi_get_private_key(an_key_t *private_key);
boolean an_udi_get_from_platform(an_udi_t *udi);
boolean an_udi_is_format_valid(an_udi_t *udi);
uint8_t* an_strTrim(uint8_t *string);
uint16_t an_udi_trim_and_get_len(uint8_t *string);
#endif
