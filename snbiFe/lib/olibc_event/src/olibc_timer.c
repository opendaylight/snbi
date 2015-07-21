/**
 * Vijay Anand R <vanandr@cisco.com>
 */
#include <string.h>
#include "olibc_timer_internal.h"
#include "olibc_pthread_internal.h"

static
void olibc_timer_cbk (int fd, short type, void *args)
{
    olibc_timer_event_t timer_event;
    olibc_timer_hdl timer_hdl = NULL;
    olibc_timer_event_func_t event_cbk = NULL;


    if (!args) {
        return;
    }

    olibc_memset(&timer_event, 0, sizeof(olibc_timer_event_t));

    timer_hdl = (olibc_timer_hdl)args;
    timer_event.timer_hdl = timer_hdl;
    event_cbk = timer_hdl->event_cbk;

    if (timer_hdl->flags & OLIBC_ONESHOT_TIMER) {
        timer_hdl->expired = TRUE;
    }

    if (event_cbk) {
        event_cbk(&timer_event);
    }
}

olibc_retval_t
olibc_timer_init (olibc_timer_hdl timer_hdl, olibc_timer_info_t *timer_info)
{
    int event_flags = 0;
    olibc_retval_t retval;
    struct event_base *evt_base = NULL;

    if (!timer_hdl || !timer_info) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if ((retval = olibc_pthread_get_event_base(timer_info->pthread_hdl,
                    &evt_base)) != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    memset(timer_hdl, 0, sizeof(olibc_timer_t));

    timer_hdl->running = FALSE;
    timer_hdl->expired = FALSE;
    timer_hdl->type = timer_info->type;
    timer_hdl->flags = timer_info->flags;
    timer_hdl->context = timer_info->context;
    timer_hdl->event_cbk = timer_info->timer_cbk;

    if (timer_info->flags & OLIBC_PERSIST_TIMER) {
        event_flags |= EV_PERSIST;
    }

    timer_hdl->event_handle = event_new(evt_base, -1, event_flags,
                                    olibc_timer_cbk, timer_hdl);

    if (!timer_hdl->event_handle) {
        return OLIBC_RETVAL_FAILED;
    }

    return OLIBC_RETVAL_SUCCESS;
}


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

    timer->running = FALSE;
    timer->expired = FALSE;
    timer->type = timer_info->type;
    timer->flags = timer_info->flags;
    timer->context = timer_info->context;
    timer->event_cbk = timer_info->timer_cbk;

    if (timer_info->flags & OLIBC_PERSIST_TIMER) {
        event_flags |= EV_PERSIST;
    }

    timer->event_handle = event_new(evt_base, -1, event_flags,
                                    olibc_timer_cbk, timer);

    if (!timer->event_handle) {
        olibc_free((void **)&timer);
        return OLIBC_RETVAL_FAILED;
    }

    *timer_hdl = timer;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_uninit (olibc_timer_hdl timer_hdl)
{
    if (!timer_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if (evtimer_del(timer_hdl->event_handle)) {
        return OLIBC_RETVAL_FAILED;
    }
    
    event_free(timer_hdl->event_handle);

    timer_hdl->event_handle = NULL;

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

    olibc_free((void **)timer_hdl);
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

    timer_hdl->running = TRUE;
    timer_hdl->expired = FALSE;

    evtimer_add(timer_hdl->event_handle, &timeout);
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_stop (olibc_timer_hdl timer_hdl)
{
    if (!timer_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    timer_hdl->running = FALSE;

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

olibc_retval_t
olibc_timer_is_running (olibc_timer_hdl timer_hdl, boolean *is_running)
{
    if (!timer_hdl || !is_running) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    *is_running = timer_hdl->running;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_is_expired (olibc_timer_hdl timer_hdl, boolean *is_expired)
{
    if (!timer_hdl || !is_expired || 
        !(timer_hdl->flags & OLIBC_ONESHOT_TIMER)) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    *is_expired = timer_hdl->expired;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_timer_event_get_hdl (olibc_timer_event_hdl event_hdl, 
                           olibc_timer_hdl *timer_hdl)
{
    if (!event_hdl || !timer_hdl) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    *timer_hdl = event_hdl->timer_hdl;

    return OLIBC_RETVAL_SUCCESS;
}
