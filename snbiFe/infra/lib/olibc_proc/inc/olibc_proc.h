/**
  *
  */
#ifndef __OLIBC_PROC_H__
#define __OLIBC_PROC_H__

#include <olibc_common.h>

typedef struct olibc_pthread_t_* olibc_pthread_hdl;

extern olibc_retval_t
olibc_pthread_create(olibc_pthread_hdl *pthread_hdl,
                     char *thread_name, void *(*start_routine)(void),
                     void *arg);
