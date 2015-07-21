/**
 * Vijay Anand R <vanandr@cisco.com>
 */
#ifndef __OLIBC_TIMER_H__
#define __OLIBC_TIMER_H__

#include <olibc_pthread.h>
#include <olibc_common.h>

#define  OLIBC_ONESHOT_TIMER 0x01
#define  OLIBC_PERSIST_TIMER 0x02

typedef struct olibc_timer_t_ *olibc_timer_hdl;
typedef struct olibc_timer_event_t_ *olibc_timer_event_hdl;

typedef boolean (*olibc_timer_event_func_t) (olibc_timer_event_hdl timer_event);

typedef struct olibc_timer_t_ {
    void *context;
    uint32_t type;
    uint32_t delay;
    uint32_t flags;
    boolean running;
    boolean expired;
    olibc_timer_event_func_t event_cbk;
    struct event *event_handle;
} olibc_timer_t;

typedef struct olibc_timer_info_t_ {
    int flags;
    void *context;
    uint32_t type;
    olibc_pthread_hdl pthread_hdl;
    olibc_timer_event_func_t timer_cbk;
} olibc_timer_info_t;


extern olibc_retval_t
olibc_timer_create(olibc_timer_hdl *timer_hdl, olibc_timer_info_t *timer_info);

extern olibc_retval_t
olibc_timer_destroy(olibc_timer_hdl *timer_hdl);

extern olibc_retval_t
olibc_timer_start(olibc_timer_hdl timer_hdl, uint32_t delay);

extern olibc_retval_t
olibc_timer_stop(olibc_timer_hdl timer_hdl);

extern olibc_retval_t
olibc_timer_reset(olibc_timer_hdl timer_hdl);

extern olibc_retval_t
olibc_timer_get_context(olibc_timer_hdl timer_hdl, void **context);

extern olibc_retval_t
olibc_timer_get_type(olibc_timer_hdl timer_hdl, uint32_t *type);

extern olibc_retval_t
olibc_timer_is_running(olibc_timer_hdl timer_hdl, boolean *is_running);

extern olibc_retval_t
olibc_timer_is_expired(olibc_timer_hdl timer_hdl, boolean *is_expired);

extern olibc_retval_t
olibc_timer_event_get_hdl(olibc_timer_event_hdl timer_event,
                          olibc_timer_hdl *timer_hdl);

extern olibc_retval_t
olibc_timer_init(olibc_timer_hdl timer_hdl, olibc_timer_info_t *timer_info);

extern olibc_retval_t
olibc_timer_uninit(olibc_timer_hdl timer_hdl);

#endif
