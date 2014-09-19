/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_BS_H__
#define __AN_BS_H__

#include "an_nbr_db.h"
#include "an_msg_mgr.h"

#define DEVICE_DOMAIN_NAMES_DELIMITER ':'
void an_bs_init(void);
void an_bs_retrieve_saved_enrollment(void);
void an_bs_uninit(void);

uint8_t *an_bs_get_nbr_state_name(an_nbr_t *nbr);
an_nbr_bs_state_e an_bs_nbr_get_state(an_nbr_t *nbr);

void an_bs_erase_unfinished_bootstrap(void);
void an_bs_set_nbr_joined_domain(an_nbr_t *nbr);
void an_bs_init_nbr_bootstrap(an_nbr_t *nbr);
void an_bs_incoming_invite_message(an_msg_package *message);
void an_bs_incoming_enroll_quarantine_message(an_msg_package *message);
void an_bs_incoming_reject_message(an_msg_package *message);
void an_bs_incoming_response_message(an_msg_package *response);
an_nbr_t *an_bs_forward_message_to_nbr(an_msg_package *message);
boolean an_bs_forward_message_to_anra(an_msg_package *message);
void an_bs_trigger_request_message(an_msg_package *invite);
boolean an_bs_is_initialized(void);
an_msg_package *an_bs_prepare_message(an_nbr_t *nbr, an_msg_type_e type);
void an_bs_trigger_nbr_connect_message(an_nbr_t *nbr);
void an_bs_bootstrap_device(an_msg_package *message);
const uint8_t *an_cert_enum_get_string(an_cert_api_ret_enum enum_type);

#endif
