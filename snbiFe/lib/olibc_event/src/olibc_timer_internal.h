/**
  * Vijay Anand R <vanandr@cisco.com>
  */
#ifndef __OLIBC_TIMER_INTERNAL_H__
#define __OLIBC_TIMER_INTERNAL_H__
#include <event2/event.h>
#include <event2/event_struct.h>
#include <olibc_timer.h>

typedef struct olibc_timer_t_ {
    void *context;
    uint32_t type;
    uint32_t delay;
    uint32_t flags;
    boolean running;
    boolean expired;
    olibc_timer_event_func_t event_cbk;
    struct event evt;
    struct event_base *evt_base;
} olibc_timer_t;

typedef struct olibc_timer_event_t_ {
    olibc_timer_hdl timer_hdl;
} olibc_timer_event_t;

#endif
