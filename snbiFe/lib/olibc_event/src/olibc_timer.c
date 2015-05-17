/**
  *
  */
#include "olibc_timer_internal.h"
#include "olibc_proc_internal.h"

olibc_retval_t
olibc_timer_create (olibc_timer_hdl *timer_hdl, olibc_timer_info_t *timer_info)
{
    int event_flags = 0;
    olibc_retval_t retval;
    struct event_base *evt_base;
    olibc_timer_t *timer = NULL;

    if (!timer_hdl || !timer_info) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    retval = olibc_malloc((void **)&timer,sizeof(olibc_timer_t), 
            __THIS_FUNCTION__);

    if (retval != OLIBC_RETVAL_SUCCESS || !timer) {
        return (timer == NULL ? OLIBC_RETVAL_MEM_ALLOC_FAILED : retval);
    }

    timer->type = timer_info->type;
    timer->context = timer_info->context;
    if ((retval = olibc_pthread_get_event_base(timer_info->pthread_hdl, 
                    &evt_base)) != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    if (timer_info->flags & OLIBC_PERSIST_TIMER) {
        event_flags |= EV_PERSIST;
    }

    timer->event_handle = event_new(evt_base, -1, event_flags,
                                    timer_info->timer_cbk, timer);

    if (!timer->event_handle) {
        return OLIBC_RETVAL_FAILED;
    }

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_destroy (olibc_timer_hdl *timer_hdl)
{
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_start (olibc_timer_hdl timer_hdl, uint32_t delay)
{
    struct timeval timeout;

    if (!timer_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    timer_hdl->delay = delay;
    timeout.tv_sec = delay/1000;
    timeout.tv_usec = (delay%1000)*1000;
    evtimer_add(timer_hdl->event_handle, &timeout);

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_stop (olibc_timer_hdl timer_hdl)
{
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_get_type (olibc_timer_hdl timer_hdl, uint32_t *type)
{
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_reset (olibc_timer_hdl timer_hdl)
{
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_get_context (olibc_timer_hdl timer_hdl, void **context)
{
    return OLIBC_RETVAL_SUCCESS;
}
