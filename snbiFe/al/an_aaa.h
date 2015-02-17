/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_AAA_H__
#define __AN_AAA_H__

#include "an_types.h"

#define AN_AAA_NO_METHOD_LIST  0
void an_aaa_set_new_model(boolean flag);
void an_aaa_enable(an_aaa_param_t *);
void an_aaa_param_set_default(an_aaa_param_t *aaa_param);
void an_aaa_update(an_aaa_param_t *aaa_param);
void an_aaa_disable(an_aaa_param_t *aaa_param);
boolean an_aaa_add_server(void);
boolean an_aaa_add_server_to_sg(an_aaa_param_t *aaa_param);
void an_aaa_param_copy_values(an_aaa_param_t *aaa_dest, an_aaa_param_t *aaa_src);
#endif
