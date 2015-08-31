/*
 * AN test cli for testing interface events.
 *
 * Anil R <anr2@cisco.com>
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
#include <olibc_if_event.h>


olibc_pthread_hdl test_if_pthread_hdl = NULL;
olibc_if_event_listener_hdl if_event_listener_hdl = NULL;

static void* 
test_pthread_routine (void *arg)
{
    printf("\nTest pthread routine started thread id %u\n", 
            (uint32_t)pthread_self());
//    sleep(SLEEP_TIME);
    olibc_pthread_dispatch_events(test_if_pthread_hdl);
    printf("Exiting pthread routine \n");
    return NULL;
}

boolean 
test_interface_event_pthread_create ()
{
    olibc_retval_t retval;
    olibc_pthread_info_t pthread_info = {0};

    pthread_info.arg = NULL;
    pthread_info.thread_name = "Test Pthread";
    pthread_info.start_routine = test_pthread_routine;

    retval = olibc_pthread_create(&test_if_pthread_hdl, &pthread_info);

    if (retval == OLIBC_RETVAL_SUCCESS) {
        uint32_t pthread_id = 0;
        olibc_pthread_get_id(test_if_pthread_hdl, &pthread_id);
        printf("Pthread creation success pid %u\n",pthread_id);
    } else {
        printf("Pthread creation failed\n");
		return FALSE;
    }
    return TRUE;
}

static boolean
test_interface_event_track_cbk (olibc_if_event_hdl if_event)
{
    olibc_retval_t retval;
    time_t timestamp;
    struct tm *ts;
    char timestr[50];
	olibc_if_iterator_hdl if_iterator_hdl = NULL;
	olibc_if_info_t if_info;

	timestamp = time(NULL);

    ts = localtime(&timestamp);
    strftime(timestr, 50, "%B %d %H:%M:%S", ts);
	
    printf("\nInside interface event track cbk - %s \n", timestr);

    if (!if_event) {
        printf("\nNull event");
        return FALSE;
    }
   
	retval = olibc_if_event_get_if_iterator (if_event,
        &if_iterator_hdl);
		
    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to get interface iterator handle");
        return FALSE;
    }

	retval = olibc_if_iterator_get_next (if_iterator_hdl,
                            &if_info);
	 if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to get interface info");
        return FALSE;
    }
	
    printf("\ninterface name: %s", if_info.if_name);
	printf("\nif_state : %s",if_info.if_state == IF_UP ?
                "IF_UP":"IF_DOWN");
    printf("\n");
    return TRUE;
}

cparser_result_t 
cparser_cmd_test_interface_event_track (cparser_context_t *context)
{
    olibc_retval_t retval;
    olibc_if_event_listener_info_t if_event_listener_info;
	if(!test_interface_event_pthread_create()) {
		return CPARSER_OK;
	}
    memset(&if_event_listener_info, 0, sizeof(olibc_if_event_listener_info_t));

    if_event_listener_info.if_event_listener_cbk = 
	test_interface_event_track_cbk;
    if_event_listener_info.pthread_hdl = test_if_pthread_hdl;
	if_event_listener_info.args = "If event listener args";
	if_event_listener_info.if_event_filter = OLIBC_FD_READ;
 
    retval = olibc_if_event_listener_create(&if_event_listener_info,
	&if_event_listener_hdl);

    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_test_interface_event_destroy (cparser_context_t *context)
{
    olibc_retval_t retval;

	retval = olibc_if_event_listener_destroy(&if_event_listener_hdl);

    printf("\nOlibc interface event destroy returned %s",
            olibc_retval_get_string(retval));
    return CPARSER_OK;
}

