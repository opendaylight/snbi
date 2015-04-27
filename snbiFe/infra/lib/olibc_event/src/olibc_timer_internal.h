/**
  */
#ifndef __OLIBC_TIMER_INTERNAL_H__
#define __OLIBC_TIMER_INTERNAL_H__
#include <event2/event.h>
#include <olibc_timer.h>

typedef struct olibc_timer_t_ {
    uint32_t type;
    uint32_t delay;
    void *context;
    struct event *event_handle;
} olibc_timer_t;

#endif
