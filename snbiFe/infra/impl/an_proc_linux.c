/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <an_proc_linux.h>

an_proc_retval_t 
an_pthread_create (an_pthread_t *an_pthread,
                   char *thread_name,
                   void *(*start_routine) (void ),
                   void *arg)
{
    pthread_t pthread_id;

    if (!an_pthread) {
        return (AN_PROC_API_INVALID_INPUT);
    }

    if (pthread_create(&pthread_id, NULL, start_routine, arg)) {
        return (AN_PROC_API_FAILED);
    }

    an_pthread->thread_id = pthread_id;
    an_pthread->thread_name = thread_name;
    an_pthread->evt_base = event_base_new();

    if (!an_pthread->evt_base) {
        return (AN_PROC_API_EVNT_BASE_ALLOC_FAILED);
    }
}  


