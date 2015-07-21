/**
  * Vijay Anand R <vanandr@cisco.com>
  */
#ifndef __OLIBC_TIMER_INTERNAL_H__
#define __OLIBC_TIMER_INTERNAL_H__
#include <event2/event.h>
#include <olibc_timer.h>

typedef struct olibc_timer_event_t_ {
    olibc_timer_hdl timer_hdl;
} olibc_timer_event_t;

#endif
