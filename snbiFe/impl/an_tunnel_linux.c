/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an.h>
#include <an_event_mgr.h>
#include <an_addr.h>
#include <an_logger.h>
#include <an_if.h>
#include <an_tunnel.h>
#include <an_if_mgr.h>
#include <an_service_discovery_linux.h>
#include <an_if_linux.h>

an_vrf_info_t an_vrf_info;
static uint32_t tunnel_num = 1;
extern olibc_list_hdl an_if_linux_list_hdl;

an_if_t
an_tunnel_create (an_addr_t *src, an_addr_t *dst, an_if_t src_if, uint8_t mode)
{
    char tunnel_name[30];
    char cmd1[200], cmd2[100],cmd3[100];
    an_if_linux_info_t *if_linux_info;
    olibc_retval_t retval;
    an_if_info_t *if_info = NULL;
    an_if_t tun_if_index;

    an_sprintf(tunnel_name, "%s%d","snbi_tun_", tunnel_num);
    while (if_nametoindex(tunnel_name)){
        tunnel_num++;
        an_sprintf(tunnel_name, "%s%d","snbi_tun_", tunnel_num);
    }

    an_sprintf(tunnel_name, "%s%d","snbi_tun_", tunnel_num);

    an_sprintf(cmd1,"%s %s %s %s %s %s %s %s", "ip -6 tunnel add", tunnel_name,
            "mode ip6gre local",an_addr_get_string(src),"remote",
            an_addr_get_string(dst), "dev", an_if_get_name(src_if));


    an_sprintf(cmd2,"%s%x:%x:%x:%d/64 %s %s","ip addr add fe80::",
            (uint16_t)(rand()%32768), (uint16_t)(rand()%32768),
            (uint16_t)(rand()%32768),tunnel_num,
            "dev",tunnel_name);

    an_sprintf(cmd3, "%s %s %s","ip link set dev", tunnel_name, "up");
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
            "\n%sTunnel Execs: \n\t %s \n\t %s \n\t %s",
            an_bs_event, cmd1, cmd2, cmd3);
    system(cmd1);
    system(cmd2);
    system(cmd3);

    retval = olibc_malloc((void **)&if_linux_info,
                    sizeof(an_if_linux_info_t), "AN linux info");


    if (!if_linux_info) {
            DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%s AN If creation failed", an_nd_event);
            return 0;
    }

    memcpy(if_linux_info->if_name, tunnel_name, strlen(tunnel_name)+1);
    tun_if_index = if_nametoindex(tunnel_name);
    if_linux_info->if_index = tun_if_index;
    if_linux_info->if_state = IF_UP;
    if_linux_info->is_loopback = FALSE;
    if_linux_info->is_tunnel = TRUE;

    retval = olibc_list_insert_node(an_if_linux_list_hdl, NULL,
                                    if_linux_info);


    if (retval != OLIBC_RETVAL_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%s AN interface insert failed", an_nd_event);
        return 0;
    }

    if_info = an_if_info_db_search(tun_if_index, TRUE);
    if (if_info) {
        if_info->autonomically_created = TRUE;
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%sTunnel num [%d] of Tunnel_name [%s] found in "
                "IF INFO DB", an_bs_event, tun_if_index,
                if_linux_info->if_name);
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%sTunnel num [%d] of Tunnel_name [%s] not found in "
                "IF INFO DB", an_bs_event, tun_if_index,
                if_linux_info->if_name);
    }
    return (tun_if_index);
}

void an_tunnel_remove (an_if_t ifhndl)
{
    char buf[100];
    char ifname[50];

    if_indextoname(ifhndl, ifname);
    an_sprintf(buf, "%s %s","ip -6 tunnel delete", ifname);
    system(buf);
    return;
}

boolean
an_vrf_unconfigure_interface (an_if_t ifhndl)
{
#ifdef PRINT_STUBS_PRINTF
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return TRUE;
}

boolean
an_vrf_configure_interface (an_if_t ifhndl)
{
#ifdef PRINT_STUBS_PRINTF
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return TRUE;
}

boolean
an_vrf_define (void)
{
#ifdef PRINT_STUBS_PRINTF
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return FALSE;
}

void
an_vrf_remove (void)
{
#ifdef PRINT_STUBS_PRINTF
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

void an_vrf_set_id (void)
{
#ifdef PRINT_STUBS_PRINTF
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

void
an_tunnel_init (void)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

void
an_tunnel_uninit (void) 
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

void an_tunnel_check_integrity (an_if_t tunn_ifhndl, an_if_t tunn_src_ifhndl)
{
}

