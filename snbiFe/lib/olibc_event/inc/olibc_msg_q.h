/**
  * Vijay Anand R
  */

#ifndef __OLIBC_MSG_Q_H__
#define __OLIBC_MSG_Q_H__

#include <olibc_common.h>
#include <olibc_pthread.h>

typedef struct olibc_msg_q_event_t_* olibc_msg_q_event_hdl;
typedef struct olibc_msg_q_t_* olibc_msg_q_hdl;

typedef boolean 
(* olibc_msg_q_event_func_t) (olibc_msg_q_event_hdl q_event_hdl);

typedef struct olibc_msg_q_info_t_ {
    uint32_t max_q_len;
    olibc_pthread_hdl pthread_hdl; 
    olibc_msg_q_event_func_t msg_q_cbk;
} olibc_msg_q_info_t;

extern olibc_retval_t
olibc_msg_q_create(olibc_msg_q_hdl *msg_q_hdl, olibc_msg_q_info_t *msg_q_info);

extern olibc_retval_t
olibc_msg_q_destroy(olibc_msg_q_hdl *msg_q_hdl);

extern olibc_retval_t
olibc_msg_q_enqueue(olibc_msg_q_hdl msg_q_hdl, uint32_t msg_type, 
                    int64_t val_arg, void *ptr_arg);

extern olibc_retval_t
olibc_msg_q_event_get_type(olibc_msg_q_event_hdl q_event_hdl, uint32_t *type);

extern olibc_retval_t
olibc_msg_q_event_get_args(olibc_msg_q_event_hdl q_event_hdl, int64_t *val_arg, 
                          void **ptr_arg);


#endif //__OLIBC_MSG_Q_H__
