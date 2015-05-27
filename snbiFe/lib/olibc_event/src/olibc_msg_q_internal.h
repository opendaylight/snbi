/**
  * Vijay Anand R
  */
#ifndef __OLIBC_MSG_Q_INTERNAL_H__
#define __OLIBC_MSG_Q_INTERNAL_H__

#include <olibc_msg_q.h>
#include "olibc_pthread_internal.h"
#include <event2/event.h>

typedef struct olibc_msg_q_node_t_ {
    uint32_t msg_type;
    int64_t val_arg;
    void *ptr_arg;
} olibc_msg_q_node_t;

typedef struct olibc_msg_q_t_ {
    uint32_t h_index;
    uint32_t t_index;
    boolean deleting;
    uint32_t max_q_len;
    pthread_cond_t cond;
    boolean event_raised;
    pthread_mutex_t mutex;
    struct event *event_handle;
    uint32_t number_q_elements;
    olibc_pthread_hdl pthread_hdl;
    olibc_msg_q_node_t *msg_q_nodes; 
    struct event *timer_event_handle;
    olibc_msg_q_event_func_t msg_q_cbk;
} olibc_msg_q_t;

typedef struct olibc_msg_q_event_t_ {
    uint32_t msg_type;
    int64_t val_arg;
    void *ptr_arg;
} olibc_msg_q_event_t;

#endif //__OLIBC_MSG_Q_INTERNAL_H__
