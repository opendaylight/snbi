/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_types.h"
#include "an_logger.h"
#include "an_addr.h"
#include "an_mem.h"
#include "an_str.h"
#include "an_sudi.h"
//#include "an_parse_dummy.h"
#include "an_acp.h"
#include "an_ipv6.h"
#include "an_misc.h"
#include "an.h"


#define AN_IPSEC_MSG_ID 0x0
#define AN_SPI 265
#define an_debug_acp 1
#define MAX_PID_LEN  18

static const char an_crypto_ss_api_debug_prefix[] = "AN ACP IPSec: ";

boolean 
an_ipsec_ss_open_close (char an_ipsec_policy[31], an_v6addr_t localip, an_v6addr_t remoteip,
                                           ushort localport, ushort remoteport,
                                           int prot, an_if_t ifhndl, boolean openflag)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
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
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
            return TRUE;
}

void an_ipsec_ss_api_listen_start(char an_ipsec_policy[31], boolean flag)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

    
boolean      
an_ipsec_create_ipsec_policy (int spi, char* an_acp_key, char an_ipsec_policy[31])
{    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return TRUE;
}

void an_ipsec_init_ss_api_layer (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}

void
an_hostname_set (uint8_t *name)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_config_save (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

boolean an_system_is_configured (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

void 
an_platform_specific_init (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void 
an_platform_specific_uninit (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

boolean
an_is_platform_type_whales2 (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return FALSE;
}

void
an_thread_check_and_suspend (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

boolean 
an_if_check_type_layer3 (an_if_t ifhndl) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return FALSE;
}

void 
an_sd_cfg_if_commands (an_if_t ifhndl, boolean set) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void 
an_process_may_suspend (void) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

boolean 
an_anra_cs_up (void) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return FALSE;
}

boolean 
an_is_active_rp (void) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return FALSE;
}

void 
an_anra_cfg_ca_server (anr_ca_server_command_e command) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
   return;
}

boolean 
an_cd_send_periodic_untagged_probe_cb (an_avl_node_t *node, void *data) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return FALSE;
}

void 
an_parser_init (void) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

