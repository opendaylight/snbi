/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <an_types.h>
#include <an.h>
#include <an_event_mgr.h>
#include <an_cert.h>
#include <an_timer.h>
#include <an_logger.h>
#include <an_mem.h>
#include <an_str.h>
#include <an_ipv6.h>


extern uint8_t sudi_trustpoint[];
an_timer an_sudi_check_timer;
#define AN_TIMER_SUDI_CHECK_INTERVAL (1*1000)
#define AN_TIMER_MAX_SUDI_CHECK_INTERVAL (1*60*1000)
#define AN_SUDI_RETRY_COUNT 5
boolean an_sudi_available = FALSE;
boolean an_sudi_initialized = FALSE;

uint8_t check_count = 0;
boolean udi_available = FALSE;

#define AN_UDI_BASE_LEN     8 
#define AN_UDI_MAX_LEN     128

/* These numbers same as that in license modiles */
#define AN_PID_MAX_LEN     18
#define AN_SN_MAX_LEN      18

#define AN_PID_PREFIX "PID:"
#define AN_UDI_INTRA_DELIMITER " "
#define AN_SN_PREFIX "SN:"

#define AN_PID_PREFIX_LEN 4
#define AN_SN_PREFIX_LEN 3
#define AN_UDI_INTRA_DELIMITER_LEN 1

boolean
an_udi_get_from_platform (an_udi_t *udi)
{

    udi->data = NULL;
    udi->len = 0;

    udi->len = AN_UDI_MAX_LEN;
    udi->data = (uint8_t *)an_malloc_guard(udi->len, "AN UDI Platform");

    if (!udi->data) {
            return (FALSE);
    }

    an_strncpy_s(udi->data, AN_UDI_MAX_LEN, "PID:LINUX SN:1", AN_UDI_MAX_LEN);
    udi->len = strlen(udi->data); 
    return TRUE;
}

/* UDI is valid if it passes the below rules:
 *
 *  1. Length < AN_UDI_MAX_LEN
 *  2. "PID:" is present
 *  3. "SN:" is present
 */
boolean
an_udi_is_format_valid (an_udi_t *udi)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

uint8_t *
an_sudi_get_label (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (NULL);
}

boolean
an_sudi_get_udi (an_udi_t *udi)
{
    return (an_udi_get_from_platform(udi));
}

boolean
an_sudi_is_available (void)
{
    return (an_sudi_available);
}


void
an_sudi_check (void)
{
    an_udi_t udi = {};
    static uint64_t time_interval = 0;

    if (!an_sudi_initialized) {
        return;
    }

    check_count++;
    if (check_count >= 100) {
        check_count = 100;
    }

    if (an_sudi_is_available()) {
        an_sudi_get_udi(&udi);
        an_set_udi(udi);
        an_event_sudi_available();
        check_count = 0;
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%sSUDI is available using it", an_nd_event);
    } else if (!udi_available) {   
        time_interval = check_count * AN_TIMER_SUDI_CHECK_INTERVAL;
        if (time_interval > AN_TIMER_MAX_SUDI_CHECK_INTERVAL) {
            time_interval = AN_TIMER_MAX_SUDI_CHECK_INTERVAL;
        }
		if (!an_is_global_cfg_autonomic_enabled()) {
            an_timer_start(&an_sudi_check_timer, time_interval);
		     return;
		}
            /* While waiting for sUDI, use UDI */
        if (udi_available) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sWhile waiting for SUDI, "
                         "UDI is already available using it", an_nd_event);

        } else if (an_udi_get_from_platform(&udi)) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sWhile waiting for SUDI, "
                         "UDI (%s) is available using it",an_nd_event, 
                         udi.data);
            an_set_udi(udi);
            an_event_udi_available();
            udi_available = TRUE;

        } else {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sWhile waiting for sUDI, Can't find the UDI",
                         an_nd_event);
        }
    }
}

/* Returns certificate pointer */
boolean
an_sudi_get_cert (an_cert_t *sudi)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (0);
}

boolean
an_sudi_get_keypair_label (uint8_t **keypair_label)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

boolean
an_sudi_get_public_key (an_key_t *key)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

boolean
an_sudi_get_private_key (an_key_t *key)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}
