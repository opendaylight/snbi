/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#ifndef __AN_SRVC_H__
#define __AN_SRVC_H__

#include "../al/an_types.h"
#include "../al/an_timer.h"
#include "an_msg_mgr.h"
#include "an_nbr_db.h"
#include "an.h"

void an_srvc_inject(an_service_type_e srvc_type, 
                                     an_addr_t* srvc_ip);
void an_srvc_incoming_message (an_msg_package *srvc_msg);
void an_srvc_incoming_ack_message (an_msg_package *srvc_ack_msg);
void an_srvc_send_message (an_udi_t nbr_udi, 
                                        an_service_info_t *srvc_info);
void an_srvc_send_ack_message (an_service_info_t *srvc_info, 
                                                         an_nbr_t *nbr);
void an_srvc_send_all_to_nbr(an_udi_t);
void an_srvc_nbr_ack_timer_expired(an_nbr_t *nbr, an_timer_e timer_type);
void an_srvc_enable (an_service_type_e srvc_type, an_addr_t* srvc_ip);
const uint8_t * an_get_srvc_type_str(an_service_type_e srvc_type);
void an_srvc_register_for_events(void);
#endif

