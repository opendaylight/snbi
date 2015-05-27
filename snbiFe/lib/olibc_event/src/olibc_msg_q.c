/**
  * Vijay Anand R <vanandr@cisco.com>
  */
#include "olibc_msg_q_internal.h"
#include <pthread.h>
#include <semaphore.h>

// 1 sec retry timer
#define MSG_Q_DESTROY_TIME 1

static void
olibc_msg_q_cbk (int fd, short type, void *args)
{
    olibc_msg_q_hdl msg_q_hdl = NULL;
    olibc_msg_q_event_t tmp_q_event_hdl;
    olibc_msg_q_node_t *msg_q_node_ptr = NULL;
    olibc_msg_q_event_func_t msg_q_cbk = NULL;

    if (!args) {
        return;
    }

    msg_q_hdl = args;
    msg_q_cbk = msg_q_hdl->msg_q_cbk;

    pthread_mutex_lock(&msg_q_hdl->mutex);
    while (msg_q_hdl->number_q_elements) {
        msg_q_node_ptr = &msg_q_hdl->msg_q_nodes[msg_q_hdl->h_index];
        tmp_q_event_hdl.msg_type = msg_q_node_ptr->msg_type;
        tmp_q_event_hdl.val_arg = msg_q_node_ptr->val_arg;
        tmp_q_event_hdl.ptr_arg = msg_q_node_ptr->ptr_arg;
        msg_q_hdl->h_index = (msg_q_hdl->h_index + 1) %
            (msg_q_hdl->max_q_len);
        msg_q_hdl->number_q_elements = msg_q_hdl->number_q_elements - 1;
        pthread_cond_signal(&msg_q_hdl->cond);
        pthread_mutex_unlock(&msg_q_hdl->mutex);

        msg_q_cbk(&tmp_q_event_hdl);

        pthread_mutex_lock(&msg_q_hdl->mutex);
    }
    // End of the event handler, raise a new event the next time.
    msg_q_hdl->event_raised = FALSE;
    pthread_mutex_unlock(&msg_q_hdl->mutex);
}

olibc_retval_t
olibc_msg_q_event_get_type (olibc_msg_q_event_hdl q_event_hdl, uint32_t *type)
{
    if (!q_event_hdl || !type) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    *type = q_event_hdl->msg_type;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t 
olibc_msg_q_event_get_args (olibc_msg_q_event_hdl q_event_hdl, int64_t *val_arg,
        void **ptr_arg)
{
    if (!q_event_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if (val_arg) {
        *val_arg = q_event_hdl->val_arg;
    }

    if (ptr_arg) {
        *ptr_arg = q_event_hdl->ptr_arg;
    }

    return OLIBC_RETVAL_SUCCESS;
}


olibc_retval_t
olibc_msg_q_create (olibc_msg_q_hdl *msg_q_hdl, olibc_msg_q_info_t *msg_q_info)
{
    olibc_retval_t retval;
    olibc_msg_q_hdl msg_q = NULL;
    olibc_msg_q_node_t *msg_q_nodes = NULL;
    struct event_base *evt_base = NULL;

    if (!msg_q_hdl || !msg_q_info  || !msg_q_info->pthread_hdl
        || !msg_q_info->max_q_len || !msg_q_info->msg_q_cbk) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if ((retval = olibc_pthread_get_event_base(msg_q_info->pthread_hdl,
                    &evt_base)) != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    retval = olibc_malloc((void **)&msg_q, sizeof(olibc_msg_q_t),
            __THIS_FUNCTION__);

    if ((retval != OLIBC_RETVAL_SUCCESS) || !msg_q) {
        return (retval != OLIBC_RETVAL_SUCCESS ? retval :
                OLIBC_RETVAL_MEM_ALLOC_FAILED);
    }

    msg_q->event_handle = event_new(evt_base, -1, EV_PERSIST | EV_READ,
                                    olibc_msg_q_cbk, msg_q);

    if (!msg_q->event_handle) {
        retval = OLIBC_RETVAL_FAILED;
        goto MSG_Q_CREATE_FAIL;
    }

    if (event_add(msg_q->event_handle, NULL)) {
        retval = OLIBC_RETVAL_FAILED;
        goto MSG_Q_CREATE_FAIL;
    }

    if (pthread_mutex_init(&msg_q->mutex, NULL)) {
        retval = OLIBC_RETVAL_FAILED;
        goto MSG_Q_CREATE_FAIL;
    }

    if (pthread_cond_init(&msg_q->cond, NULL)) {
        retval = OLIBC_RETVAL_FAILED;
        pthread_mutex_destroy(&msg_q->mutex);
        goto MSG_Q_CREATE_FAIL;
    }

    retval = olibc_malloc((void **)&msg_q_nodes,
            sizeof(olibc_msg_q_node_t)*msg_q_info->max_q_len,
            __THIS_FUNCTION__);

    if ((retval != OLIBC_RETVAL_SUCCESS) || !msg_q_nodes) {
        pthread_cond_destroy(&msg_q->cond);
        pthread_mutex_destroy(&msg_q->mutex);
        retval = (retval != OLIBC_RETVAL_SUCCESS ? retval :
                OLIBC_RETVAL_MEM_ALLOC_FAILED);
        goto MSG_Q_CREATE_FAIL;
    }

    msg_q->event_raised = FALSE;
    msg_q->msg_q_nodes = msg_q_nodes;
    msg_q->msg_q_cbk = msg_q_info->msg_q_cbk;
    msg_q->max_q_len = msg_q_info->max_q_len;
    msg_q->pthread_hdl = msg_q_info->pthread_hdl;
    *msg_q_hdl = msg_q;

    return OLIBC_RETVAL_SUCCESS;
MSG_Q_CREATE_FAIL:
    if (msg_q) {
        if (msg_q->event_handle) {
            event_free(msg_q->event_handle);
        }
        olibc_free((void **)&msg_q);
    }
    return retval;
}

static void
olibc_msg_q_destroy_internal (olibc_msg_q_hdl msg_q_hdl)
{
    if (!msg_q_hdl) {
        return;
    }

    printf("\n In internal q destroy");
    if (msg_q_hdl->timer_event_handle) {
        evtimer_del(msg_q_hdl->timer_event_handle);
        event_free(msg_q_hdl->timer_event_handle);
        msg_q_hdl->timer_event_handle = NULL;
    }

    if (msg_q_hdl->event_handle) {
        event_del(msg_q_hdl->event_handle);
        event_free(msg_q_hdl->event_handle);
        msg_q_hdl->event_handle = NULL;
    }

    olibc_free((void **)&msg_q_hdl->msg_q_nodes);

    olibc_free((void **)&msg_q_hdl);
}

static void 
olibc_msg_q_destroy_timer_cbk (int fd, short type, void *args)
{
    olibc_msg_q_hdl msg_q_hdl;

    if (!args) {
        return;
    }

    msg_q_hdl = args;

    if (msg_q_hdl->number_q_elements) {
        struct timeval timeout;

        olibc_memset(&timeout, 0, sizeof(struct timeval));

        timeout.tv_sec = MSG_Q_DESTROY_TIME;
        evtimer_add(msg_q_hdl->timer_event_handle, &timeout);
        return;
    }
    
    printf("\n In msg_q_ call back timer");
    olibc_msg_q_destroy_internal(msg_q_hdl);
}


olibc_retval_t 
olibc_msg_q_destroy (olibc_msg_q_hdl *msg_q_hdl)
{
    olibc_retval_t retval;
    olibc_msg_q_hdl msg_q;
    struct event_base *evt_base = NULL;


    if (!msg_q_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    msg_q = *msg_q_hdl;

    if (msg_q->deleting) {
        *msg_q_hdl = NULL;
        return OLIBC_RETVAL_SUCCESS;
    }

    msg_q->deleting = TRUE;

    if (msg_q->number_q_elements) {
        struct timeval timeout;

        if ((retval = olibc_pthread_get_event_base(msg_q->pthread_hdl, 
                                                   &evt_base)) != 
                OLIBC_RETVAL_SUCCESS) {
            return retval;
        }
        olibc_memset(&timeout, 0, sizeof(struct timeval));

        msg_q->timer_event_handle = event_new(evt_base, -1, EV_PERSIST,
                                              olibc_msg_q_destroy_timer_cbk, 
                                              msg_q);
        timeout.tv_sec = MSG_Q_DESTROY_TIME;
        evtimer_add(msg_q->timer_event_handle, &timeout);
        return OLIBC_RETVAL_SUCCESS;
    }

    olibc_msg_q_destroy_internal(msg_q);

    *msg_q_hdl = NULL;

    return OLIBC_RETVAL_SUCCESS;
}


olibc_retval_t
olibc_msg_q_enqueue (olibc_msg_q_hdl msg_q_hdl, 
                     uint32_t msg_type, 
                     int64_t val_arg, void *ptr_arg) 
{
    olibc_msg_q_node_t *msg_q_node = NULL;
    if (!msg_q_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    pthread_mutex_lock(&msg_q_hdl->mutex);
    while ((msg_q_hdl->number_q_elements
        == msg_q_hdl->max_q_len) && msg_q_hdl->event_raised) {
        pthread_cond_wait(&msg_q_hdl->cond, &msg_q_hdl->mutex);
        // conditional wait if an event is already raised.
        // we need a while loop here, to handle multiple producers 
    }

    if (msg_q_hdl->number_q_elements >= msg_q_hdl->max_q_len) {
        // Some thing really really wrong.
        pthread_mutex_unlock(&msg_q_hdl->mutex);
        return (OLIBC_RETVAL_FAILED);
    }

    if (msg_q_hdl->deleting) {
        pthread_mutex_unlock(&msg_q_hdl->mutex);
        return OLIBC_RETVAL_FAILED;
    }

    msg_q_node = &msg_q_hdl->msg_q_nodes[msg_q_hdl->t_index];
    msg_q_node->msg_type = msg_type;
    msg_q_node->val_arg = val_arg;
    msg_q_node->ptr_arg = ptr_arg;
    msg_q_hdl->t_index = (msg_q_hdl->t_index+1)%(msg_q_hdl->max_q_len);
    msg_q_hdl->number_q_elements = msg_q_hdl->number_q_elements + 1;

    if (!msg_q_hdl->event_raised) {
        event_active(msg_q_hdl->event_handle, EV_WRITE, 0);
        msg_q_hdl->event_raised = TRUE;
    }
    pthread_mutex_unlock(&msg_q_hdl->mutex);

    return OLIBC_RETVAL_SUCCESS;
}
