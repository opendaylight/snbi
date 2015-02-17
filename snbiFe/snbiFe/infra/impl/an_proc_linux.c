/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */



#include "an_proc_linux.h"
#include "an_types_linux.h"
#include <pthread.h>

#define AN_GROUP "FF02::150"

pthread_t an_thread;
boolean an_initialised = FALSE;
boolean an_socket_open = FALSE;
int an_sockfd = 0;
struct sockaddr_in6 serv_addr, client_addr;
struct sockaddr_storage sender;
socklen_t sendsize = sizeof(sender);
boolean platform_ready = FALSE;

boolean
an_udp_pak_enqueue (an_pak_t *pak, char *udp_block)
{
//    an_udp_hdr_t *udp_hdr = NULL;
/*
    if (!pak || !udp_block) {
        return (FALSE);
    }
*/
    if (!pak) {
        return (FALSE);
    }

//    udp_hdr = (an_udp_hdr_t *)udp_block;
/*
    if ((udp_hdr->dest_port != AN_UDP_PORT) ||
        (udp_hdr->source_port != AN_UDP_PORT)) {
        return (FALSE);
    }

    if (!an_pak_enqueue(pak)) {
        return (FALSE);
    }
*/

    an_msg_mgr_receive_an_message(pak->data, pak, pak->ifhndl);    
    an_pak_free(pak);
    return (TRUE);
}

static void
an_process (void)
{
    printf("\n Inside AN PROCESS func..!");
    struct ipv6_mreq mreq;
    int no_of_bytes_received = 0;
    char buffer[256];
    an_pak_t *pak;
    uint32_t ifhndl;    
   
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(AN_UDP_PORT);

    if (bind(an_sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) != 0) {
    //      perror( "Bind Failure: " );
  //      exit( 1 );
    }

//    inet_pton(AF_INET6, AN_GROUP, &mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_multiaddr = an_ll_scope_all_node_mcast.ipv6_addr;
    mreq.ipv6mr_interface = 0;

    if (setsockopt(an_sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&mreq, sizeof(mreq)) != 0) {
       // perror( "IPV6_JOIN_GROUP" );
       // exit( 1 );
    }


    while (TRUE) {

        memset(buffer, '\0', 256);
        no_of_bytes_received = recvfrom(an_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&sender, &sendsize);

        if (no_of_bytes_received>0) {
            pak = (an_pak_t*)an_malloc(sizeof(an_pak_t), "AN Linux Pak");
            if (pak) {
                ifhndl = an_get_ifhndl_from_sockaddr (&sender);
                an_linux_pak_create(pak, ifhndl, buffer, &sender);
                if(an_udp_pak_enqueue(pak, NULL)){
                    printf("\n AN_UDP_PAK_ENQUEUE Succesfull");
                }
            }    
        }



    }


} 

void
an_init (void) {

    int retval;

    retval = pthread_create(&an_thread, NULL, (void *) &an_process, NULL);

    if (retval != 0) {
        DEBUG_AN_LOG(AN_LOG_SRVC_NTP, AN_DEBUG_SEVERE, NULL,
                                 "\n AN Thread creation failed..!!");
       exit(0);
    }

}

void
an_attach_to_environment (void) {
    /* Create AN socket */

    an_sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (an_sockfd < 0) {
        DEBUG_AN_LOG(AN_LOG_ALL_ALL, AN_DEBUG_SEVERE, NULL,
                                 "\nSocket Opening failed, exiting..!!");
        exit(0);
    }

    printf("\n Socket Created Succesfully..");

    an_socket_open = TRUE;

    an_init();    
    /* Infra enable for AN */
//    an_if_services_init();
    return;
}

void
an_uninit (void) {

    /* Wait till threads are complete before an_init continues. Unless we  */
    /* wait we run the risk of executing an exit which will terminate      */
    /* the process and all threads before the threads have completed.      */

    pthread_join(an_thread, NULL);

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
an_pak_enqueue (an_pak_t *pak)
{
/*
    if (process_enqueue(an_message_q, pak)) {
        return (TRUE);
    }
    return (FALSE);
*/
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
    return;
}

