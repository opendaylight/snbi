/****************************************************
 *
 * an_timer_linux.h
 *
 * July 2014, Sandeep Kumar Chawan S
 *
 * Copyright (c) 2011-2014 by cisco Systems, Inc.
 * All rights reserved.
 *
 * Timer functionality for AN. Interacts with Linux
 * Timer implementation.
 *
 ****************************************************/
#ifndef __AN_TIMER_LINUX_H__
#define __AN_TIMER_LINUX_H__

#include "an_types.h"
//#include "an_timer.h"
#include <time.h>
#include <signal.h>

typedef struct an_linux_timer_t_ {
    int signum;
    uint32_t type;
    timer_t timerid;
    void *context;
} an_linux_timer_t;

#endif
