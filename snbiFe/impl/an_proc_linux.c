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
#include "an_linux_sock.h"

#define AN_GROUP "FF02::150"

olibc_pthread_hdl an_pthread_hdl = NULL;
boolean an_initialised = FALSE;

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

void
an_attach_to_environment (void) 
{
    /* Create AN socket */
    an_linux_sock_create();
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

