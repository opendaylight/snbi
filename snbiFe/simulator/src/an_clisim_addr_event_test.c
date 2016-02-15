/*
 * AN test cli for testing address events.
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
#include <olibc_addr_event.h>


olibc_pthread_hdl test_addr_pthread_hdl = NULL;
olibc_addr_event_listener_hdl addr_event_listener_hdl = NULL;

static void*
test_addr_event_pthread_routine (void *arg)
{
    printf("\nTest pthread routine started thread id %u\n",
            (uint32_t)pthread_self());
    olibc_pthread_dispatch_events(test_addr_pthread_hdl);
    printf("Exiting pthread routine \n");
    return NULL;
}

boolean
test_addr_event_pthread_create ()
{
    olibc_retval_t retval;
    olibc_pthread_info_t pthread_info = {0};

    pthread_info.arg = NULL;
    pthread_info.thread_name = "Test Address Pthread";
    pthread_info.start_routine = test_addr_event_pthread_routine;

    retval = olibc_pthread_create(&test_addr_pthread_hdl, &pthread_info);

    if (retval == OLIBC_RETVAL_SUCCESS) {
        uint32_t pthread_id = 0;
        olibc_pthread_get_id(test_addr_pthread_hdl, &pthread_id);
        printf("Pthread creation success pid %u\n",pthread_id);
    } else {
        printf("Pthread creation failed\n");
        return FALSE;
    }
    return TRUE;
}

static boolean
test_addr_event_track_cbk (olibc_addr_event_hdl addr_event)
{
    struct tm *ts;
    char timestr[50];
    time_t timestamp;
    uint32_t if_index;
    olibc_retval_t retval;
    olibc_addr_info_t addr_info;
    char ip_str[INET6_ADDRSTRLEN];
    olibc_addr_event_type_t event_type;
    olibc_addr_iterator_hdl addr_iterator_hdl = NULL;

    timestamp = time(NULL);

    ts = localtime(&timestamp);
    strftime(timestr, 50, "%B %d %H:%M:%S", ts);

    printf("\nInside addr event track cbk - %s \n", timestr);

    if (!addr_event) {
        printf("\nNull event");
        return FALSE;
    }

    retval = olibc_addr_event_get_iterator(addr_event,
                                           &addr_iterator_hdl);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to get addr iterator handle");
        return FALSE;
    }

    memset(&addr_info, 0, sizeof(olibc_addr_info_t));

    while (olibc_addr_iterator_get_next(addr_iterator_hdl, &addr_info,
           &if_index, &event_type) == OLIBC_RETVAL_SUCCESS) {
        printf("\nIf_index %d", if_index);
        if (addr_info.addr_family == AF_INET) {
            inet_ntop(addr_info.addr_family, &addr_info.addrv4, ip_str,
                    sizeof(ip_str));
        }
        if (addr_info.addr_family == AF_INET6) {
            inet_ntop(addr_info.addr_family, &addr_info.addrv6, ip_str,
                     sizeof(ip_str));
        }
        if (event_type == ADDR_EVENT_NEW) {
            printf("\nAddress Add event");
        }
        if (event_type == ADDR_EVENT_DEL) {
            printf("\nAddress Del event");
        }
        printf("\nIP address %s/%d",ip_str, addr_info.prefixlen);
        printf("\n");
        memset(&addr_info, 0, sizeof(olibc_addr_info_t));
    }
    return TRUE;
}

cparser_result_t
cparser_cmd_test_interface_addr_track (cparser_context_t *context)
{
    olibc_retval_t retval;
    olibc_addr_event_listener_info_t addr_event_listener_info;

    if(!test_addr_event_pthread_create()) {
        return CPARSER_OK;
    }

    memset(&addr_event_listener_info, 0,
           sizeof(olibc_addr_event_listener_info_t));

    addr_event_listener_info.addr_event_listener_cbk =
    test_addr_event_track_cbk;
    addr_event_listener_info.pthread_hdl = test_addr_pthread_hdl;
    addr_event_listener_info.args = "Address event listener args";
    addr_event_listener_info.flags = (OLIBC_FLAG_IPV6 | OLIBC_FLAG_IPV4);

    retval = olibc_addr_event_listener_create(&addr_event_listener_info,
                                              &addr_event_listener_hdl);

    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_addr_event_destroy (cparser_context_t *context)
{
    olibc_retval_t retval;

    retval = olibc_addr_event_listener_destroy(&addr_event_listener_hdl);

    printf("\nOlibc addr event destroy returned %s",
            olibc_retval_get_string(retval));
    return CPARSER_OK;
}

