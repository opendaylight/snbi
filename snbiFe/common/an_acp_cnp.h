/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#ifndef __AN_ACP_CNP_H__
#define __AN_ACP_CNP_H__

#include "../al/an_types.h"
#include "an_nbr_db.h"
#include "an_msg_mgr.h"

typedef struct an_acp_cap_set_ {
    uint16_t length;
    uint16_t member_length;
    uint8_t *value;
} an_acp_cap_set_t;

typedef enum an_acp_cnp_param_e_ {
    AN_ACP_CNP_PARAM_NONE,
    AN_ACP_CNP_PARAM_SECURE_CHANNEL,
} an_acp_cnp_param_e;

void an_acp_negotiate_secure_channel_per_nbr_link(an_nbr_t *nbr,
                                                  an_nbr_link_spec_t *nbr_link_data);
boolean an_acp_cnp_init(void);
void an_acp_set_default_cap_set(uint16_t param_id);
boolean an_acp_cnp_uninit(void);

boolean an_acp_cnp_is_vrf_applicable(void);
void an_cnp_uninit(void);
void an_cnp_init(void);
void
an_cnp_receive_pak(an_msg_package *message_pk);
#endif
