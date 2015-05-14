/*
 * AN test cli for testing events.
 *
 * Vijay Anand R
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "an_types.h"
#include "an_mem.h"
#include <unistd.h>
#include <cparser.h>
#include <olibc_proc.h>
#include <cparser_tree.h>


olibc_pthread_hdl test_pthread_hdl;

int  SLEEP_TIME = 60*1;

static void* 
test_pthread_routine (void *arg)
{
    printf("Test pthread routine started thread id %u\n", 
            (uint32_t)pthread_self());
    sleep(SLEEP_TIME);
    printf("Exiting pthread routine \n");
    return NULL;
}

cparser_result_t 
cparser_cmd_test_event_pthread_create(cparser_context_t *context)
{
    olibc_retval_t retval;
    olibc_pthread_info_t pthread_info = {0};

    pthread_info.arg = NULL;
    pthread_info.thread_name = "Test Pthread";
    pthread_info.start_routine = test_pthread_routine;

    retval = olibc_pthread_create(&test_pthread_hdl, &pthread_info);

    if (retval == OLIBC_RETVAL_SUCCESS) {
        uint32_t pthread_id = 0;
        olibc_pthread_get_id(test_pthread_hdl, &pthread_id);
        printf("Pthread creation success pid %u \n",pthread_id);
    } else {
        printf("Pthread creation failed\n");
    }
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_test_event_timer_create(cparser_context_t *context)
{
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_test_event_timer_destroy(cparser_context_t
        *context)
{
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_test_event_timer_start(cparser_context_t *context)
{
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_test_event_timer_stop(cparser_context_t *context)
{
    return CPARSER_OK;
}
