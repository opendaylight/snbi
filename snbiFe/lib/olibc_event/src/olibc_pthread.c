/**
  * Vijay Anand R <vanandr@cisco.com>
  */
#include <string.h>
#include <stdlib.h>
#include <event2/event.h>
#include "olibc_pthread_internal.h"

//olibc_hash_hdl pthread_hash_list_hdl = NULL;


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

#if 0

    if (pthread_hash_list) {
        olibc_hash_info_t hash_info;
        memset(&hash_info, 0, sizeof(olibc_hash_info_t));

        hash_info.size = 10;
        hash_info.algorithm_type = OLIBC_HASH_DEFAULT;
        hash_info.name = "Pthread Hash list";

        retval = olibc_hash_create(&pthread_hash_list_hdl, &hash_info);
        if (retval != OLIBC_RETVAL_SUCCESS) {
            return retval;
        }
    }
#endif
        
    retval = olibc_malloc((void **)&pthread, 
                           sizeof(olibc_pthread_t), 
                          __THIS_FUNCTION__);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return (retval);
    }

    if (!pthread) {
        return OLIBC_RETVAL_MEM_ALLOC_FAILED;
    }

    if (pthread_info->thread_name) {
        pthread->thread_str = strdup(pthread_info->thread_name);
    }
    pthread->arg = pthread_info->arg;

    pthread->evt_base = event_base_new();
    if (!pthread->evt_base) {
        free(pthread->thread_str);
        olibc_free((void **)&pthread);
        return OLIBC_RETVAL_FAILED;
    }

    if (pthread_create(&pthread_id, NULL, pthread_info->start_routine,
                       pthread)) {
        free(pthread->thread_str);
        olibc_free((void **)&pthread);
        return (OLIBC_RETVAL_FAILED);
    }

    pthread->thread_id = pthread_id;

    *pthread_hdl = pthread;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pthread_get_arg (olibc_pthread_hdl pthread_hdl, void** arg)
{
    if (!pthread_hdl || !arg) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    *arg = pthread_hdl->arg;
    return (OLIBC_RETVAL_SUCCESS);
}

olibc_retval_t
olibc_pthread_dispatch_events (olibc_pthread_hdl pthread_hdl)
{
    if (!pthread_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    event_base_loop(pthread_hdl->evt_base, EVLOOP_NO_EXIT_ON_EMPTY);

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pthread_get_id (olibc_pthread_hdl pthread_hdl,
                      uint32_t *pthread_id)
{
    if (!pthread_hdl || !pthread_id) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    *pthread_id = pthread_hdl->thread_id;
    return OLIBC_RETVAL_SUCCESS;
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

    *evt_base = pthread_hdl->evt_base;
    return OLIBC_RETVAL_SUCCESS;
}

extern olibc_retval_t
olibc_pthread_dispatch_events_stop (olibc_pthread_hdl pthread_hdl)
{
    if (!pthread_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    event_base_loopexit(pthread_hdl->evt_base, NULL);
    return OLIBC_RETVAL_SUCCESS;
}
