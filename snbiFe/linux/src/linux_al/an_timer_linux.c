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

// Move this to a common linux file. 
#define SIGTIMER     (SIGRTMAX)

// Move this to a common linux file. 
#define AN_LINUX_ERROR -1

void an_handle_timer_events (int signo, siginfo_t * info, void *context)
{
    an_timer *timer = NULL;

    timer = (an_timer *)info->si_value.sival_ptr;
}

void an_timer_services_init (void)
{
    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = an_handle_timer_events;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTIMER, &sa, NULL) == AN_LINUX_ERROR) {
        perror("sigaction failed");
    }
}

void
an_timer_init (an_timer *timer, an_timer_e timer_type,
               void *context, boolean interrupt)
{
    struct sigevent sigev;

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
    struct itimerspec tspec;

    if (timer == NULL) {
        return;
    }

    tspec.it_value.tv_sec = delay / 1000;
    tspec.it_value.tv_nsec = (delay * 1000000) % 1000000000;
    tspec.it_interval.tv_sec = tspec.it_value.tv_sec;
    tspec.it_interval.tv_nsec = tspec.it_value.tv_nsec;

    if (timer_settime(timer->timerid, 0, &tspec, NULL) == AN_LINUX_ERROR) {
        perror("Failed to start timer");
    }

}

void
an_timer_stop (an_timer *timer) 
{ 
    struct itimerspec tspec;
    tspec.it_value.tv_sec = 0;
    tspec.it_value.tv_nsec = 0;

    if (timer == NULL) {
        return;
    }

    if (timer_settime(timer->timerid, 0, &tspec, NULL) 
            == AN_LINUX_ERROR) {
        perror("Failed to start timer");
    }
}

an_log_type_e an_get_log_timer_type(an_timer_e timer_type)
{
    return (AN_LOG_NONCE);
}

uint32_t
an_mgd_timer_type (an_mgd_timer *expired_timer)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

void
an_timer_reset (an_timer *timer, uint32_t delay)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void *
an_mgd_timer_context (an_mgd_timer *expired_timer)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (NULL);
}

const uint8_t *
an_timer_get_timer_type_str (an_timer_e timer_type)
{   
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (NULL);
}

