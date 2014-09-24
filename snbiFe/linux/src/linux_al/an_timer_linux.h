/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


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
