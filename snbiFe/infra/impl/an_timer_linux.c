/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <time.h>
#include <signal.h>
#include "an_types.h"
#include "an_event_mgr.h"
#include "an_if_mgr.h"
#include "an_anra.h"  
#include "an_timer.h"
#include "an_mem.h"
#include "an_sudi.h"
#include "an_logger.h"
#include "an_if.h"
#include "an_timer_linux.h"

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
void an_handle_linux_timer_events (int signo, siginfo_t * info, void *context)
{
    an_timer *timer = NULL;

    timer = (an_timer *)info->si_value.sival_ptr;

    an_process_timer_events(timer);
}

void an_timer_services_init (void)
{
    struct sigaction sa = {{0}};

    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = an_handle_linux_timer_events;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTIMER, &sa, NULL) == AN_LINUX_ERROR) {
        perror("sigaction failed");
    }
}

void
an_timer_init (an_timer *timer, an_timer_e timer_type,
               void *context, boolean interrupt)
{
    struct sigevent sigev = {{0}};

    if (timer == NULL) {
        return;
    }

    timer->type = timer_type;
    // Create the POSIX timer to generate signo
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = SIGTIMER;
    sigev.sigev_value.sival_ptr = timer;
    timer->context = context;

    if (timer_create(CLOCK_REALTIME, &sigev, &timer->timerid) 
            == AN_LINUX_ERROR) {
        perror("sigaction failed");
    }
}

void
an_timer_uninit (an_timer *timer) 
{
    timer_delete(timer->timerid);
}

/**
  * delay in milli seconds.
  */
void
an_timer_start (an_timer *timer, uint32_t delay)
{
    struct itimerspec tspec = {{0}};

    if (timer == NULL) { 
        return;
    }

    tspec.it_value.tv_sec = delay / 1000;
    tspec.it_value.tv_nsec = (delay * 1000000) % 1000000000;
    tspec.it_interval.tv_sec = tspec.it_value.tv_sec;
    tspec.it_interval.tv_nsec = tspec.it_value.tv_nsec;
//#if 0
    if (timer_settime(timer->timerid, 0, &tspec, NULL) == AN_LINUX_ERROR) {
        perror("\nFailed to start timer");
    }
//#endif    
}

void
an_timer_stop (an_timer *timer) 
{ 
    struct itimerspec tspec = {{0}};
    if (timer == NULL) {
        return;
    }

    memset(&tspec, 0, sizeof(struct itimerspec));

    if (timer_settime(timer->timerid, 0, &tspec, NULL) 
            == AN_LINUX_ERROR) {
        perror("\t\tFailed to stop timer");
    }
}

uint32_t
an_mgd_timer_type (an_mgd_timer *expired_timer)
{
    if (expired_timer == NULL) {
        return AN_LOG_NONCE;
    }

    return (expired_timer->type);
}

void
an_timer_reset (an_timer *timer, uint32_t delay)
{
printf("\n\t\t\t\t[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void *
an_mgd_timer_context (an_mgd_timer *expired_timer)
{
    return (expired_timer->context);
}

const uint8_t *
an_timer_get_timer_type_str (an_timer_e timer_type)
{   
    return (an_timer_type_str[timer_type]);
}

/* Edit the below 3 funcs */
boolean
an_timer_is_running (an_timer *timer)
{
//        return an_timer_initialized;
    return FALSE;
}

boolean
an_timer_is_expired (an_timer *timer)
{
        return (FALSE);
}

void
an_timer_start64 (an_timer *timer, int64_t delay)
{
}


