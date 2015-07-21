/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_logger.h>
#include <an_addr.h>
#include <an_if.h>
#include <an_ntp.h>
#include <an_tunnel.h>
#include <an_event_mgr.h>
#include <an_list.h>


void
an_clock_set (void)
{   
    return;
}

boolean an_ntp_add_remove_master (uint32_t stratum, boolean remove)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return TRUE;
}

boolean an_ntp_set_peer (an_ntp_peer_param_t *ntp_peer, boolean
        is_peer_association)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return FALSE;
}

boolean
an_ntp_remove_peer (an_ntp_peer_param_t *ntp_peer, boolean is_peer_association)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return FALSE;
}

void
an_ntp_do_calendar_update (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

an_unix_time_t 
an_unix_time_get_current_timestamp (void) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return 0;	
}

boolean an_unix_time_is_elapsed(an_unix_time_t timestamp,
                                an_unix_time_t elapse_interval) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return FALSE;
}

void 
an_unix_time_get_diff_between_timestamps(an_unix_time_t new_timestamp,
                                              an_unix_time_t old_timestamp,
                                              uint8_t *time_diff_str) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void 
an_unix_time_get_elapsed_time_str(an_unix_time_t timestamp,
                                       uint8_t *elapsed_time_str) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void 
an_unix_time_timestamp_conversion(an_unix_time_t timestamp,
                                       uint8_t *converted_time) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

an_unix_time_t 
an_unix_time_get_elapsed_time(an_unix_time_t timestamp) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    an_unix_time_t dummy_time={0};
    return (dummy_time);
}

boolean
an_ntp_is_system_clock_valid (void)
{
        return TRUE;
}

