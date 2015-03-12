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

#define TIME_DIFF_STR 80

//boolean an_ntp_enable(boolean is_anra, an_v6addr_t peerip, an_iptable_t iptable);
void an_ntp_do_calendar_update(void);
//boolean an_ntp_disable(boolean is_anra, an_v6addr_t peerip, an_if_t ifhndl);
void an_ntp_clock_sync_from_ntp(void);
void an_clock_set(void);

boolean an_ntp_add_remove_master(uint32_t stratum, boolean remove);
boolean an_ntp_set_peer(an_ntp_peer_param_t *ntp_peer, boolean is_peer_association);
boolean an_ntp_remove_peer(an_ntp_peer_param_t *ntp_peer, boolean is_peer_association);

an_unix_time_t an_unix_time_get_current_timestamp(void);
boolean an_unix_time_is_elapsed(an_unix_time_t timestamp, 
                                an_unix_time_t elapse_interval);
void an_unix_time_get_diff_between_timestamps(an_unix_time_t new_timestamp,
                                              an_unix_time_t old_timestamp,
                                              uint8_t *time_diff_str);
void an_unix_time_get_elapsed_time_str(an_unix_time_t timestamp,
                                       uint8_t *elapsed_time_str);
void an_unix_time_timestamp_conversion(an_unix_time_t timestamp,
                                       uint8_t *converted_time);
an_unix_time_t an_unix_time_get_elapsed_time(an_unix_time_t timestamp);
boolean an_ntp_is_system_clock_valid(void);
#define AN_NTP_MASTER_STRATUM     4
#define AN_NTP_REFCLOCK           0x7f7f0101

#endif
