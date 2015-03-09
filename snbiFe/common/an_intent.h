/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_INTENT_H__
#define __AN_INTENT_H__
#include "../al/an_types.h"

typedef enum an_intent_config_err_e_ {
    AN_INTENT_CONFIG_ERR_NONE = 0,
} an_intent_config_err_e;

an_intent_config_err_e an_intent_delete(void);
void an_intent_parse_file_if_available(void);
void an_intent_register_for_events(void);
void an_intent_init(void);
#endif
