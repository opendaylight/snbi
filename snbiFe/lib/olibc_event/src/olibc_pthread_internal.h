/**
  * Vijay Anand R <vanandr@cisco.com>
  */
#ifndef __OLIBC_PROC_PRIVATE_H__
#define __OLIBC_PROC_PRIVATE_H__

#include <pthread.h>
#include <olibc_pthread.h>
#include <event2/event.h>

typedef struct olibc_pthread_t_ {
    void *arg;
    char *thread_str;
    pthread_t thread_id;
    struct event_base *evt_base;
} olibc_pthread_t;

extern olibc_retval_t
olibc_pthread_get_event_base(olibc_pthread_hdl pthread_hdl, 
                             struct event_base **evt_base);

#endif
