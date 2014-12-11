/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "an_types.h"

boolean an_key_generate_keypair(uint8_t *key_label);
boolean an_key_remove_keypair(uint8_t *key_label);
boolean an_key_check(uint8_t *key_label);
boolean an_key_get_public_key(uint8_t *key_label, an_key_t *key);
boolean an_key_get_private_key(uint8_t *key_label, an_key_t *key);
