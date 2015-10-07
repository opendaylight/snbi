#ifndef __OLIBC_IF_EVENT_H__
#define __OLIBC_IF_EVENT_H__

#include <olibc_common.h>
#include <olibc_net.h>
#include <olibc_if.h>
#include <olibc_pthread.h>
#include <olibc_fd_event.h>

typedef struct olibc_if_event_listener_t_* olibc_if_event_listener_hdl;
typedef struct olibc_if_event_t_* olibc_if_event_hdl;
typedef boolean (*olibc_if_event_listener_func_t) 
    (olibc_if_event_hdl if_event);

typedef struct olibc_if_event_listener_info_t_ {
    void *args;
    olibc_if_event_listener_func_t if_event_listener_cbk;
    olibc_pthread_hdl pthread_hdl;
} olibc_if_event_listener_info_t;

olibc_retval_t
olibc_if_event_listener_create(olibc_if_event_listener_info_t 
        *if_event_listener_info, olibc_if_event_listener_hdl
        *if_event_listener_hdl);

olibc_retval_t
olibc_if_event_listener_destroy(olibc_if_event_listener_hdl 
        *if_event_listener_hdl);

olibc_retval_t
olibc_if_event_get_if_iterator(olibc_if_event_hdl event_hdl, 
        olibc_if_iterator_hdl *if_iterator_hdl); 

olibc_retval_t
olibc_if_event_get_args(olibc_if_event_hdl event_hdl, void** args); 

#endif
