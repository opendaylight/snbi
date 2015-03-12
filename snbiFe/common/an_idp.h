/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_IDP_H__
#define __AN_IDP_H__

#include "../al/an_types.h"
#include "an_msg_mgr.h"

void an_idp_init(void);
void an_idp_uninit(void);
void an_idp_register_for_events(void);
boolean
an_idp_hton_version(an_intent_ver_t *target,
                     an_intent_ver_t src);
an_intent_ver_t
an_idp_ntoh_version(uint8_t *src);
void an_idp_incoming_intent_message_v2
		(an_msg_package *intent_msg, an_if_t ifhndl);
void an_idp_incoming_intent_version_message_v2
		(an_msg_package *intent_msg, an_if_t ifhndl);
void an_idp_incoming_intent_request_message_v2
		(an_msg_package *intent_msg, an_if_t ifhndl);
void an_idp_incoming_ack_message_v2
		(an_msg_package *ack, an_if_t ifhndl);
void
an_idp_nbr_retransmit_timer_expired(void);
void
an_idp_nbr_ack_timer_expired_v2(an_nbr_t *nbr);
#endif
