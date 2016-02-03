/*
 * AN test cli for testing events.
 *
 * Vijay Anand R <vanandr@cisco.com>
 *
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
#include <olibc_pthread.h>
#include <cparser_tree.h>
#include <olibc_msg_q.h>
#include <event2/event.h>
#include <time.h>


olibc_pthread_hdl test_pthread_hdl = NULL;
olibc_timer_hdl test_timer_hdl = NULL;
olibc_timer_hdl test_timer_hdl_2 = NULL;
olibc_timer_hdl test_timer_hdl_1 = NULL;
olibc_msg_q_hdl test_msg_q_hdl = NULL;
#define TIMER_TYPE_1 1
#define TIMER_TYPE_2 2

int  SLEEP_TIME = 5*1;

void write_to_stdbout_cb (int severity, const char *msg)
{
   const char *s;

    switch (severity) {
        case _EVENT_LOG_DEBUG: s = "debug"; break;
        case _EVENT_LOG_MSG:   s = "msg";   break;
        case _EVENT_LOG_WARN:  s = "warn";  break;
        case _EVENT_LOG_ERR:   s = "error"; break;
        default:               s = "?";     break; /* never reached */
    }
    printf("[%s] %s\n", s, msg);
}

cparser_result_t 
cparser_cmd_test_event_logging_stdout (cparser_context_t *context)
{
    event_enable_debug_mode();
    event_enable_debug_logging(EVENT_DBG_ALL);
    event_set_log_callback(write_to_stdbout_cb);
            
    return CPARSER_OK;
}

static void* 
test_pthread_routine (void *arg)
{
    printf("\nTest pthread routine started thread id %u\n", 
            (uint32_t)pthread_self());
//    sleep(SLEEP_TIME);
    olibc_pthread_dispatch_events(test_pthread_hdl);


    printf("Exiting pthread routine \n");
    return NULL;
}

cparser_result_t 
cparser_cmd_test_event_pthread_create (cparser_context_t *context)
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
static boolean
test_timer_routine_reset_cbk (olibc_timer_event_hdl tmp_event_hdl)
{
    static int cnt = 0;
    olibc_timer_hdl timer_hdl = NULL;
    olibc_retval_t retval;
    time_t timestamp;
    struct tm *ts;
    char timestr[50];
    uint32_t type;

    memset(timestr, 0 , 50);

    timestamp = time(NULL);

    ts = localtime(&timestamp);
    strftime(timestr, 50, "%B %d %H:%M:%S", ts);

    retval = olibc_timer_event_get_hdl(tmp_event_hdl, &timer_hdl);
    retval = olibc_timer_get_type(timer_hdl, &type);

    printf("\n%s - Inside test timer reset routine cbk type %d\n", timestr, 
           type);
    sleep(SLEEP_TIME);
    timestamp = time(NULL);

    ts = localtime(&timestamp);
    strftime(timestr, 50, "%B %d %H:%M:%S", ts);

    printf("\n%s - Wokeup from sleep", timestr);

    if (type == TIMER_TYPE_1 && cnt < 10) {
        printf("\ntimer2 reset");
        olibc_timer_reset(test_timer_hdl_2);
        olibc_timer_stop(test_timer_hdl_1);
        olibc_timer_start(test_timer_hdl_1, 2200);
        cnt++;
    } else {
        printf("\n count %d, no reset", cnt);
    }
    return TRUE;
}

static boolean
test_timer_routine_cbk (olibc_timer_event_hdl tmp_event_hdl)
{
    uint32_t type;
    char *context = NULL;
    olibc_retval_t retval;
    olibc_timer_hdl timer_hdl = NULL;
    time_t timestamp;
    struct tm *ts;
    char timestr[50];

    memset(timestr, 0 , 50);

    timestamp = time(NULL);

    ts = localtime(&timestamp);
    strftime(timestr, 50, "%B %d %H:%M:%S", ts);

    printf("\nInside test timer routine cbk - %s \n", timestr);

    if (!tmp_event_hdl) {
        printf("\nNull event handle");
        return FALSE;
    }

    retval = olibc_timer_event_get_hdl(tmp_event_hdl, &timer_hdl);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to get timer handle from event handle %s",
                olibc_retval_get_string(retval));
        return FALSE;
    }

    retval = olibc_timer_get_type(timer_hdl, &type);
    if (retval == OLIBC_RETVAL_SUCCESS) {
        printf("\nTimer type %d", type);
    } else {
        printf("\nFailed to get timer type");
        return FALSE;
    }

    retval = olibc_timer_get_context(timer_hdl, (void **)&context);

    if (retval == OLIBC_RETVAL_SUCCESS) {
        printf("\nContext returned is %s\n",context ? context:"NULL");
    } else {
        printf("\nFailed to get context\n");
    }
    return TRUE;
}

cparser_result_t 
cparser_cmd_test_event_timer_create (cparser_context_t *context)
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

cparser_result_t 
cparser_cmd_test_event_timer_destroy (cparser_context_t *context)
{
    olibc_retval_t retval;

    retval = olibc_timer_destroy(&test_timer_hdl);

    printf("\nOlibc timer destroy returned %s",
            olibc_retval_get_string(retval));
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

cparser_result_t
cparser_cmd_test_event_timer_reset (cparser_context_t *context)
{
    /*
    olibc_retval_t retval;

    retval = olibc_timer_reset(test_timer_hdl);

    printf("\nTimer reset returned %s", olibc_retval_get_string(retval));
    */
    olibc_retval_t retval;
    olibc_timer_info_t timer_info;
    memset(&timer_info, 0, sizeof(olibc_timer_info_t));

    timer_info.flags |= OLIBC_ONESHOT_TIMER;
    timer_info.timer_cbk = test_timer_routine_reset_cbk;
    timer_info.pthread_hdl = test_pthread_hdl;
    timer_info.context = (void*)"Test timer";
    timer_info.type = TIMER_TYPE_1;
    retval = olibc_timer_create(&test_timer_hdl_1, &timer_info);
    retval = olibc_timer_start(test_timer_hdl_1, 2200);

    timer_info.type = TIMER_TYPE_2;
    retval = olibc_timer_create(&test_timer_hdl_2, &timer_info);
    retval = olibc_timer_start(test_timer_hdl_2, 2201);
    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_test_event_timer_stop (cparser_context_t *context)
{
    olibc_retval_t retval;

    retval = olibc_timer_stop(test_timer_hdl);

    printf("\nTimer stop returned %s", olibc_retval_get_string(retval));
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_event_stop_evnt_loop (cparser_context_t *context)
{
    olibc_retval_t retval;
    retval = olibc_pthread_dispatch_events_stop(test_pthread_hdl);

    printf("Stop event returned %s \n", olibc_retval_get_string(retval));

    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_test_event_timer_running (cparser_context_t *context)
{
    olibc_retval_t retval;
    boolean is_running = FALSE;

    retval = olibc_timer_is_running(test_timer_hdl, &is_running);

    printf("Timer is running returned %s is running = %s\n",
            olibc_retval_get_string(retval), is_running ? "TRUE":"FALSE");
    return CPARSER_OK;
}

boolean
test_msg_q_cbk (olibc_msg_q_event_hdl q_event_hdl)
{
    olibc_retval_t retval;
    int64_t val;
    uint32_t type;
    char *ptr = NULL;

    if (!q_event_hdl)
        return FALSE;

    retval = olibc_msg_q_event_get_type(q_event_hdl, &type);

    retval = olibc_msg_q_event_get_args(q_event_hdl, &val, 
                                        (void **)&ptr);
    
    printf("\nIn test_msg_q_cbk msg Type %d, msg val %ld msg_ptr %s",
            type, (long)val, ptr ? (char *)ptr:"NULL");
    sleep(5);
    return TRUE;
}

cparser_result_t 
cparser_cmd_test_event_msg_q_create (cparser_context_t *context)
{
    olibc_retval_t retval;
    olibc_msg_q_info_t msg_q_info;

    memset(&msg_q_info, 0, sizeof(msg_q_info));

    msg_q_info.max_q_len = 10;
    msg_q_info.pthread_hdl = test_pthread_hdl;
    msg_q_info.msg_q_cbk = test_msg_q_cbk;

    retval = olibc_msg_q_create(&test_msg_q_hdl, &msg_q_info);
    printf("Msg q create returned %s", olibc_retval_get_string(retval));
    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_test_event_msg_q_destroy(cparser_context_t *context)
{
    olibc_retval_t retval;

    retval = olibc_msg_q_destroy(&test_msg_q_hdl);
    printf("\nMsg Q destroy returned %s", olibc_retval_get_string(retval));
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_event_msg_q_enqueue_msgtype_valarg_ptrarg (
        cparser_context_t *context, uint32_t *msgtype_ptr, 
        uint32_t *valarg_ptr, char **ptrarg_ptr)
{
    olibc_retval_t retval;
    char *str = strdup((char *)*ptrarg_ptr);

    retval = olibc_msg_q_enqueue(test_msg_q_hdl, 
            *msgtype_ptr, (int64_t)
            (*valarg_ptr), (void *)str);

    printf("Msg Q enqueue returned %s", olibc_retval_get_string(retval));
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_event_msg_q_scale (cparser_context_t *context)
{
    olibc_retval_t retval;
    int i = 10;
    while (i) {
        retval = olibc_msg_q_enqueue(test_msg_q_hdl, i+9900, i, "Hello world");
        printf("\nolibc_msg_q_enqueue returned %s",
                olibc_retval_get_string(retval));
        i--;
    }

    return CPARSER_OK;
}
