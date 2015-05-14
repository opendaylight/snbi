/**
  *
  */
#ifndef __OLIBC_PROC_H__
#define __OLIBC_PROC_H__

#include <olibc_common.h>

typedef struct olibc_pthread_t_* olibc_pthread_hdl;
typedef void* (*olibc_pthread_start_func) (void *);

typedef struct olibc_pthread_info_t_ {
    void *arg;
    char *thread_name;
    olibc_pthread_start_func start_routine;
} olibc_pthread_info_t;

extern olibc_retval_t
olibc_pthread_create(olibc_pthread_hdl *pthread_hdl,
                     olibc_pthread_info_t *pthread_info);

extern olibc_retval_t
olibc_pthread_get_id(olibc_pthread_hdl pthread_hdl, uint32_t *thread_id);

extern olibc_retval_t
olibc_pthread_destroy(olibc_pthread_hdl *pthread_hdl);

#endif
