/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_TIMER_H__
#define __AN_TIMER_H__

#include "an_types.h"

typedef enum an_timer_e_ {
    AN_TIMER_TYPE_NONE = 0,
    AN_TIMER_TYPE_SUDI_CHECK,
    AN_TIMER_TYPE_IF_BRING_UP,
    AN_TIMER_TYPE_NI_CERT_REQUEST,
    AN_TIMER_TYPE_PER_NBR_LINK_CLEANUP,
    AN_TIMER_TYPE_HELLO_REFRESH,
    AN_TIMER_TYPE_IDP_REFRESH,
    AN_TIMER_TYPE_IDP_REQUEST,
    AN_TIMER_TYPE_AAA_INFO_SYNC,
    AN_TIMER_TYPE_ANR_CS_CHECK,
    AN_TIMER_TYPE_GENERIC,    
    AN_TIMER_TYPE_MAX,
} an_timer_e;

an_log_type_e an_get_log_timer_type(an_timer_e timer_type);

const uint8_t * an_timer_get_timer_type_str(an_timer_e timer_type);
void an_timer_services_init(void);
void an_timer_services_uninit(boolean);

void an_timer_init(an_timer *timer, an_timer_e timer_enum, 
                    void *context, boolean interrupt);
void an_timer_uninit(an_timer *timer);

void an_timer_start(an_timer *timer, uint32_t delay);
void an_timer_stop(an_timer *timer);
void an_timer_reset(an_timer *timer, uint32_t delay);
void an_timer_update(an_timer *timer, uint32_t delay);

uint32_t an_mgd_timer_type(an_timer *expired_timer);
void *an_mgd_timer_context(an_timer *expired_timer);
void an_process_timer_events(an_timer *expired_timer);

#endif
