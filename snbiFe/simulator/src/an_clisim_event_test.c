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


olibc_pthread_hdl test_pthread_hdl = NULL;
olibc_timer_hdl test_timer_hdl = NULL;

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
        printf("Pthread creation success pid %u\n",pthread_id);
    } else {
        printf("Pthread creation failed\n");
    }
    return CPARSER_OK;
}

static void test_timer_routine_cbk (int fd, short ev_type, void *args)
{
    char *context = NULL;
    olibc_timer_hdl timer_hdl = (olibc_timer_hdl) args;
    olibc_retval_t retval;
    uint32_t type;

    printf("\nInside test timer routine cbk");

    if (!args) {
        return;
    }

    retval = olibc_timer_get_type(timer_hdl, &type);
    if (retval == OLIBC_RETVAL_SUCCESS) {
        printf("Timer type %d", type);
    } else {
        printf("Failed to get timer type");
        return;
    }

    retval = olibc_timer_get_context(timer_hdl, (void **)&context);

    if (retval == OLIBC_RETVAL_SUCCESS) {
        printf("Context returned is %s",context ? context:"NULL");
    } else {
        printf("Failed to get context");
    }
}

cparser_result_t cparser_cmd_test_event_timer_create(cparser_context_t *context)
{
    olibc_retval_t retval;
    olibc_timer_info_t timer_info;
    memset(&timer_info, 0, sizeof(olibc_timer_info_t));

    timer_info.flags |= OLIBC_PERSIST_TIMER;
    timer_info.timer_cbk = test_timer_routine_cbk;
    timer_info.pthread_hdl = test_pthread_hdl;
    timer_info.context = (void*)"Test timer";
 
    retval = olibc_timer_create(&test_timer_hdl, &timer_info);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_test_event_timer_destroy(cparser_context_t
        *context)
{
    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_test_event_timer_start_value (cparser_context_t *context, 
                                          uint32_t *value_ptr)
{
    olibc_retval_t retval;

    retval = olibc_timer_start(test_timer_hdl, *value_ptr);

    if (retval == OLIBC_RETVAL_SUCCESS) {
        printf("Timer start success for %d seconds\n", *value_ptr);
    } else {
        printf("Timer start failed\n");
    }
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_test_event_timer_stop(cparser_context_t *context)
{
    return CPARSER_OK;
}
