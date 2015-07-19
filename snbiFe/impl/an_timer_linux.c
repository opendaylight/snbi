/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <time.h>
#include <signal.h>
#include <an_types.h>
#include <an_event_mgr.h>
#include <an_if_mgr.h>
#include <an_anra.h>
#include <an_timer.h>
#include <an_mem.h>
#include <an_sudi.h>
#include <an_logger.h>
#include <an_if.h>

static const uint8_t *an_timer_type_str[] = {
    "None",
    "Sudi Check",
    "If bring UP",
    "NI Cert Req",
    "Nbr Per Link Cleanup",
    "Hello Refresh",
    "Idp Refresh",
    "Idp Request",
    "AAA Info Sync",
    "ANR CS Check",
    "Generic Timer",
    "Max Timer"
};

an_log_type_e an_get_log_timer_type(an_timer_e timer_type)
{
    switch(timer_type) {
        case AN_TIMER_TYPE_SUDI_CHECK:
        case AN_TIMER_TYPE_IF_BRING_UP:
        case AN_TIMER_TYPE_NI_CERT_REQUEST:
        case AN_TIMER_TYPE_PER_NBR_LINK_CLEANUP:
        case AN_TIMER_TYPE_HELLO_REFRESH:
             return (AN_LOG_ND_EVENT);
        case AN_TIMER_TYPE_IDP_REFRESH:
        case AN_TIMER_TYPE_IDP_REQUEST:
        case AN_TIMER_TYPE_AAA_INFO_SYNC:
        case AN_TIMER_TYPE_GENERIC:
             return (AN_LOG_SRVC_EVENT);
        case AN_TIMER_TYPE_ANR_CS_CHECK:
             return (AN_LOG_RA_EVENT);
        default:
             break;
    }
    return (AN_LOG_NONCE);

}


//boolean an_handle_timer_events (void)
boolean 
an_handle_linux_timer_events (olibc_timer_event_hdl timer_event)
{
    printf("\n (%s)",__FUNCTION__);
    return TRUE;
}

void an_timer_services_init (void)
{
}

void
an_timer_init (an_timer *timer_hdl_ptr, an_timer_e timer_type,
               void *context, boolean interrupt)
{
    olibc_retval_t retval;
    olibc_timer_info_t timer_info;

    memset(&timer_info, 0, sizeof(olibc_timer_info_t));
    timer_info.flags |= OLIBC_PERSIST_TIMER;
    timer_info.timer_cbk = an_handle_linux_timer_events;
    timer_info.context = context;
    timer_info.pthread_hdl = an_pthread_hdl;

    retval = olibc_timer_create(timer_hdl_ptr, &timer_info);
}

void
an_timer_uninit (an_timer *timer_hdl_ptr) 
{
    olibc_retval_t retval;
    retval = olibc_timer_destroy(timer_hdl_ptr);
}

/**
  * delay in milli seconds.
  */
void
an_timer_start (an_timer *timer_hdl_ptr, uint32_t delay)
{
    olibc_timer_hdl timer_hdl;
    olibc_retval_t retval;

    timer_hdl = *timer_hdl_ptr;
    retval = olibc_timer_start(timer_hdl, delay);
}

void
an_timer_stop (an_timer *timer_hdl_ptr) 
{ 
    olibc_timer_hdl timer_hdl;
    olibc_retval_t retval;

    timer_hdl = *timer_hdl_ptr;

    retval = olibc_timer_stop(timer_hdl);
}


uint32_t
an_mgd_timer_type (an_mgd_timer *timer_hdl_ptr)
{
    uint32_t type = 0;
    olibc_retval_t retval;
    olibc_timer_hdl timer_hdl;

    timer_hdl = *timer_hdl_ptr;

    retval = olibc_timer_get_type(timer_hdl, &type);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return 0;
    }
    return type;
}

void
an_timer_reset (an_timer *timer_hdl_ptr, uint32_t delay)
{
    olibc_retval_t retval;
    olibc_timer_hdl timer_hdl;

    timer_hdl = *timer_hdl_ptr;
    retval = olibc_timer_reset(timer_hdl);
    return;
}

void *
an_mgd_timer_context (an_mgd_timer *timer_hdl_ptr)
{
    void *context;
    olibc_retval_t retval;
    olibc_timer_hdl timer_hdl;

    timer_hdl = *timer_hdl_ptr;
    retval = olibc_timer_get_context(timer_hdl, &context);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return NULL;
    }
    return context;
}

const uint8_t *
an_timer_get_timer_type_str (an_timer_e timer_type)
{   
    return (an_timer_type_str[timer_type]);
}

/* Edit the below 3 funcs */
boolean
an_timer_is_running (an_timer *timer_hdl_ptr)
{
    olibc_retval_t retval;
    boolean is_running = FALSE;
    olibc_timer_hdl timer_hdl;

    timer_hdl = *timer_hdl_ptr;
    retval = olibc_timer_is_running(timer_hdl, &is_running);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }
    return is_running;
}

boolean
an_timer_is_expired (an_timer *timer_hdl_ptr)
{
    olibc_retval_t retval;
    olibc_timer_hdl timer_hdl;
    boolean is_expired = FALSE;

    timer_hdl = *timer_hdl_ptr;

    retval = olibc_timer_is_expired(timer_hdl, &is_expired);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }
    return (is_expired);
}

void
an_timer_start64 (an_timer *timer, int64_t delay)
{
    printf("\n %s not defined",__FUNCTION__);
}
