/**
  */
#include <string.h>
#include <stdlib.h>
#include <event2/event.h>
#include "olibc_proc_internal.h"


olibc_retval_t
olibc_pthread_create (olibc_pthread_hdl *pthread_hdl,
                      olibc_pthread_info_t *pthread_info)
{
    olibc_retval_t retval;
    pthread_t pthread_id;
    olibc_pthread_t *pthread = NULL;

    if (!pthread_hdl || !pthread_info || !pthread_info->start_routine) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if (pthread_create(&pthread_id, NULL, pthread_info->start_routine,
                       pthread_info->arg)) {
        return (OLIBC_RETVAL_FAILED);
    }

    if (!pthread_hdl) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    retval = olibc_malloc((void **)&pthread, 
                           sizeof(olibc_pthread_t), 
                          __THIS_FUNCTION__);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return (retval);
    }

    if (!pthread) {
        return OLIBC_RETVAL_MEM_ALLOC_FAILED;
    }

    pthread->thread_id = pthread_id;

    if (pthread_info->thread_name) {
        pthread->thread_str = strdup(pthread_info->thread_name);
    }
}

olibc_retval_t
olibc_pthread_destory (olibc_pthread_hdl *pthread_hdl)
{
    olibc_pthread_t *pthread  = NULL;
    if (!pthread_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    pthread = *pthread_hdl;

    free(pthread->thread_str);
    olibc_free((void **)pthread_hdl);
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pthread_get_event_base (olibc_pthread_hdl pthread_hdl, 
                              struct event_base **evt_base)
{
    if (!pthread_hdl || !evt_base) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if (!pthread_hdl->evt_base) {
        pthread_hdl->evt_base = event_base_new();
    }
    *evt_base = pthread_hdl->evt_base;
}
