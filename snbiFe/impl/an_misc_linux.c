/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_logger.h>
#include <an_addr.h>
#include <an_mem.h>
#include <an_str.h>
#include <an_sudi.h>
//#include <an_parse_dummy.h>
#include <an_acp.h>
#include <an_ipv6.h>
#include <an_misc.h>
#include <an.h>
#include <an_if.h>
#include "an_cert_linux.h"
#include "an_conf_linux.h"
#include  <signal.h>
#include "../common/an.h"
#include <pthread.h>
#include <time.h>
#include <an_conf_linux.h>

#define AN_IPSEC_MSG_ID 0x0
#define AN_SPI 265
#define an_debug_acp 1
#define MAX_PID_LEN  18
#define WAIT_TIME_SECONDS       60

pthread_mutex_t     quit_sig_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t      quit_sig_con = PTHREAD_COND_INITIALIZER;

static const char an_crypto_ss_api_debug_prefix[] = "AN ACP IPSec: ";

boolean 
an_ipsec_ss_open_close (char an_ipsec_policy[31], an_v6addr_t localip, an_v6addr_t remoteip,
                                           ushort localport, ushort remoteport,
                                           int prot, an_if_t ifhndl, boolean openflag)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return (TRUE);
}

/*
 * an_crypto_ss_api_listen
 * AN specific listen function;  which will be called when incoming
 * IPSec negotiation arrive and the proxies in that negotiating 
 * are requesting security with some application on the box.
 * Our job is to decide whether we are "that" application and
 * do we want to accept the request
 */
boolean an_ipsec_ss_api_listen (an_crypto_ss_cnct_id *cnct_id,
                                     char *profile_name, ulong *flags)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
            return TRUE;
}

void an_ipsec_ss_api_listen_start(char an_ipsec_policy[31], boolean flag)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

    
boolean      
an_ipsec_create_ipsec_policy (int spi, char* an_acp_key, char an_ipsec_policy[31])
{    
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return TRUE;
}

void an_ipsec_init_ss_api_layer (void)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

void
an_hostname_set (uint8_t *name)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void
an_config_save (void)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

boolean an_system_is_configured (void)
{
    return (TRUE);
}

void 
an_platform_specific_init (void)
{
    an_openssl_init();
    return;
}

void 
an_platform_specific_uninit (void)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

boolean
an_is_platform_type_whales2 (void)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return FALSE;
}

void
an_thread_check_and_suspend (void)
{
    return;
}

boolean 
an_if_check_type_layer3 (an_if_t ifhndl) {
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return FALSE;
}

void 
an_sd_cfg_if_commands (an_if_t ifhndl, boolean set) {
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void 
an_process_may_suspend (void) {
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

boolean 
an_anra_cs_up (void) {
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return FALSE;
}

boolean 
an_is_active_rp (void) 
{
    return TRUE;
}

void 
an_anra_cfg_ca_server (anr_ca_server_command_e command) {
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
   return;
}

boolean 
an_cd_send_periodic_untagged_probe_cb (an_avl_node_t *node, void *data) {
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return FALSE;
}

void 
an_parser_init (void) 
{
    return;
}

boolean
an_is_startup_config_exists(void)
{
    return FALSE;
}

an_ifs_pathent *an_config_ifs_pathent_create (void)
{
    return NULL;
}

void
an_config_ifs_build_pathent (an_ifs_pathent *src_pathent,
                                     an_config_param_t config_sd_param_global,
                                                                  uint8_t
                                                                  an_file_name[200])
{
}

void
an_config_ifs_build_path_from_pathent (an_ifs_pathent *src_pathent)
{
}
char*
an_config_ifs_get_path (an_ifs_pathent *src_pathent)
{
        return (NULL);
}
char*
an_config_ifs_get_filename (an_ifs_pathent *src_pathent)
{
    return NULL;
}
void
an_config_download_send_message (an_ifs_pathent *src_pathent, ulong value)
{
}

void
an_config_tftp_set_source_idb (void)
{
}

void
an_config_tftp_reset_source_idb (void)
{
}


void  INThandler(int sig)
{
    int rValue;
    struct timespec ts;
    struct timeval    tp;

    if (sig) {
        printf("SNBI Process is exiting due to Ctrl-C hit\n");
    }
    gettimeofday(&tp, NULL);
    ts.tv_sec  = tp.tv_sec;
    ts.tv_nsec = tp.tv_usec * 1000;
    ts.tv_sec += WAIT_TIME_SECONDS;
    rValue = pthread_mutex_lock(&quit_sig_mutex);
    an_disable_cmd_handler();
    pthread_cond_timedwait(&quit_sig_con, &quit_sig_mutex,&ts);
    rValue = pthread_mutex_unlock(&quit_sig_mutex);
    an_config_global_cleanup_cmd_handler();
    exit(0);
}
void an_register_for_sig_quit (void)
{
     signal(SIGINT, INThandler);
}
