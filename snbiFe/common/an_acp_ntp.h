/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#ifndef __AN_ACP_NTP_H__
#define __AN_ACP_NTP_H__

#include "../al/an_types.h"
#include "an_nbr_db.h"

void
an_acp_ntp_nbr_link_cleanup(an_nbr_link_spec_t *nbr_link_data);
void an_acp_ntp_anr_locally_up_event(void);
void an_acp_ntp_anr_shut_event(void);
void an_acp_ntp_start_clock_sync_nbr(an_nbr_t *nbr);
void an_acp_remove_clock_sync_with_nbr(an_nbr_t *nbr);
boolean an_acp_enable_clock_sync_with_nbr(an_nbr_t *nbr);
void an_acp_ntp_peer_remove_global(an_nbr_t *nbr);
void an_acp_start_ntp_with_ra(an_addr_t address);
void an_acp_start_ntp_with_nbrs(void);
void an_acp_enable_clock_sync_with_ra(an_addr_t address);
#endif
