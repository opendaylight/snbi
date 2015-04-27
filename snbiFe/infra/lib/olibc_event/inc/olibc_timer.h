/**
  *
  */
#ifndef __OLIBC_TIMER_H__
#define __OLIBC_TIMER_H__

#include <olibc_proc.h>
#include <olibc_common.h>

#define  OLIBC_ONSHOT_TIMER 0x01
#define  OLIBC_PERSIST_TIMER 0x02

typedef void (*olibc_event_cbk) (int fd, short type, void *args);

typedef struct olibc_timer_info_t_ {
    int flags;
    void *context;
    uint32_t type;
    olibc_event_cbk timer_cbk;
    olibc_pthread_hdl pthread_hdl;
} olibc_timer_info_t;

typedef struct olibc_timer_t_ *olibc_timer_hdl;

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

#endif
