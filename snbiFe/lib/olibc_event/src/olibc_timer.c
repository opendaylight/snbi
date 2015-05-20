/**
  * Vijay Anand R <vanandr@cisco.com>
  */
#include "olibc_timer_internal.h"
#include "olibc_pthread_internal.h"

olibc_retval_t
olibc_timer_create (olibc_timer_hdl *timer_hdl, olibc_timer_info_t *timer_info)
{
    int event_flags = 0;
    olibc_retval_t retval;
    olibc_timer_t *timer = NULL;
    struct event_base *evt_base = NULL;

    if (!timer_hdl || !timer_info) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if ((retval = olibc_pthread_get_event_base(timer_info->pthread_hdl,
                    &evt_base)) != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    retval = olibc_malloc((void **)&timer,sizeof(olibc_timer_t), 
            __THIS_FUNCTION__);

    if (retval != OLIBC_RETVAL_SUCCESS || !timer) {
        return (timer == NULL ? OLIBC_RETVAL_MEM_ALLOC_FAILED : retval);
    }

    timer->type = timer_info->type;
    timer->context = timer_info->context;

    if (timer_info->flags & OLIBC_PERSIST_TIMER) {
        event_flags |= EV_PERSIST;
    }

    timer->event_handle = event_new(evt_base, -1, EV_PERSIST,
                                    timer_info->timer_cbk, timer);

    if (!timer->event_handle) {
        olibc_free((void **)&timer);
        return OLIBC_RETVAL_FAILED;
    }

    *timer_hdl = timer;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_destroy (olibc_timer_hdl *timer_hdl)
{
    olibc_timer_hdl timer = NULL;


    if (!timer_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    timer = *timer_hdl;

    if (evtimer_del(timer->event_handle)) {
        return OLIBC_RETVAL_FAILED;
    }
    
    event_free(timer->event_handle);

    olibc_free(timer_hdl);
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_start (olibc_timer_hdl timer_hdl, uint32_t delay)
{
    struct timeval timeout;

    if (!timer_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    olibc_memset(&timeout, 0, sizeof(struct timeval));

    timeout.tv_sec = delay/1000;
    timeout.tv_usec = (delay%1000)*1000;
    timeout.tv_sec = delay;
    timeout.tv_usec = 0;

    evtimer_add(timer_hdl->event_handle, &timeout);
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_stop (olibc_timer_hdl timer_hdl)
{
    if (!timer_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    evtimer_del(timer_hdl->event_handle);
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_get_type (olibc_timer_hdl timer_hdl, uint32_t *type)
{
    if (!timer_hdl || !type) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    *type = timer_hdl->type;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_reset (olibc_timer_hdl timer_hdl)
{
    if (!timer_hdl) {
        return OLIBC_RETVAL_SUCCESS;
    }

    olibc_timer_stop(timer_hdl);
    olibc_timer_start(timer_hdl, timer_hdl->delay);

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_get_context (olibc_timer_hdl timer_hdl, void **context)
{
    if (!timer_hdl || !context) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    *context = timer_hdl->context;

    return OLIBC_RETVAL_SUCCESS;
}
