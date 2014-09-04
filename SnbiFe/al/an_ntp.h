/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_NTP_H__
#define __AN_NTP_H__

#include "an_types.h"
#include "../common/an_nbr_db.h"
//boolean an_ntp_enable(boolean is_anra, an_v6addr_t peerip, an_iptable_t iptable);
void an_ntp_do_calendar_update(void);
//boolean an_ntp_disable(boolean is_anra, an_v6addr_t peerip, an_if_t ifhndl);
void an_ntp_clock_sync_from_ntp(void);
void an_clock_set(void);

boolean an_ntp_add_remove_master(uint32_t stratum, boolean remove);
boolean an_ntp_set_peer(an_ntp_peer_param_t *ntp_peer);
boolean an_ntp_remove_peer(an_ntp_peer_param_t *ntp_peer);

#define AN_NTP_MASTER_STRATUM     8
#define AN_NTP_REFCLOCK           0x7f7f0101

#endif
