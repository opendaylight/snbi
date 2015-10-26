/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <an_proc_linux.h>
#include <an_types_linux.h>
#include <olibc_pthread.h>
#include <olibc_msg_q.h>
#include "an_sock_linux.h"

#define AN_GROUP "FF02::150"

olibc_pthread_hdl an_pthread_hdl = NULL;
boolean an_initialised = FALSE;
olibc_msg_q_hdl an_pmsg_q_hdl = NULL;

static void*
an_linux_process (void *arg)
{
    olibc_pthread_dispatch_events(an_pthread_hdl);
    return NULL;
}

void an_proc_init (void)
{
    olibc_retval_t retval;
    olibc_pthread_info_t pthread_info;

    if (an_pthread_hdl) {
        // Process is already inited.
        return;
    }

    memset(&pthread_info, 0,sizeof(olibc_pthread_info_t));
    pthread_info.start_routine = an_linux_process;
    pthread_info.thread_name = "AN Process";
    pthread_info.arg = NULL;

    retval = olibc_pthread_create(&an_pthread_hdl, &pthread_info);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\n*********************************************");
        printf("\n****** AN System initialization failed ******");
        printf("\n*********************************************");
        exit(0);
    }
    return;
}

static boolean
an_pmsg_q_cbk (olibc_msg_q_event_hdl q_event_hdl)
{
    uint32_t msg_type, if_hndl;
    uint64_t if_index;
    olibc_retval_t retval;

    if (!q_event_hdl) {
        return FALSE;
    }

    retval = olibc_msg_q_event_get_type(q_event_hdl, &msg_type);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }

    switch (msg_type) {
        case AN_PMSG_IF_UP:
            retval = olibc_msg_q_event_get_args(q_event_hdl, &if_index, NULL);
            if (retval != OLIBC_RETVAL_SUCCESS) {
                  printf("\nFailed to get interface index");
                  return FALSE;
              }
            if_hndl = (uint32_t) if_index;
            an_handle_interface_up(if_index);
            break;

        case AN_PMSG_IF_DOWN:
            retval = olibc_msg_q_event_get_args(q_event_hdl, &if_index, NULL);
            if (retval != OLIBC_RETVAL_SUCCESS) {
                  printf("\nFailed to get interface index");
                  return FALSE;
            }
            if_hndl = (uint32_t) if_index;
            an_handle_interface_down(if_index);
            break;

        default:
            printf("\nUnknown type event received");
            return FALSE;
    }
    return TRUE;
}

boolean
an_pmsg_q_init ()
{
    olibc_retval_t retval;
    olibc_msg_q_info_t msg_q_info;

    if (!an_pthread_hdl) {
        return FALSE;
    }

    memset(&msg_q_info, 0, sizeof(olibc_msg_q_info_t));

    msg_q_info.max_q_len = 10;
    msg_q_info.pthread_hdl = an_pthread_hdl;
    msg_q_info.msg_q_cbk = an_pmsg_q_cbk;

    retval = olibc_msg_q_create(&an_pmsg_q_hdl, &msg_q_info);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }
    return TRUE;
}


void
an_attach_to_environment (void)
{
    /* Create AN pmsg queue */
    an_pmsg_q_init();
    /* Create AN socket */
    an_linux_sock_init();
    /* Infra enable for AN */
    an_if_services_init();
    /* Add the interfaces to AN db */
    an_if_init();
    return;
}

void
an_detach_from_environment (void)
{
    an_if_services_uninit();
}

void
an_proc_uninit (void)
{
    /* Wait till threads are complete before an_init continues. Unless we  */
    /* wait we run the risk of executing an exit which will terminate      */
    /* the process and all threads before the threads have completed.      */
    olibc_pthread_destroy(&an_pthread_hdl);
    printf("\npthread_join() - Thread stopped...\n");
}

boolean
is_an_initialised (void)
{
    return (an_initialised);
}

void
an_process_send_message (an_thread_t pid, const char *key, ulong message_num, void *pointer, ulong message_arg) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_process_call(void){
/* Schedule AN process to handle transition */
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_process_call_shut(void) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_process_call_no_registrar(uint32_t value_chk) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

boolean
an_is_system_configured_completely(void) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return FALSE;
}

void
an_process_set_boolean(an_watched_boolean *watch_bool) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

boolean
an_process_get_boolean(an_watched_boolean *watch_bool) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return FALSE;
}

