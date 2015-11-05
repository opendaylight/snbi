/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
//#include <an_parse_dummy.h>
#include <an_ipv6.h>
#include <an_logger.h>
#include <an_routing.h>
#include <an_if.h>
#include <an_if_mgr.h>
#include <an.h>
#include <an_addr.h>
#include <an_external_anra.h>
#include <an_str.h>


void an_rpl_global_enable(an_rpl_info_t *an_rpl_info)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void an_notify_routing_device_id_availble()
{
    char device_id_prefix[50];
    char cmd[500];
    char *external_ra = NULL;
    an_addr_t external_ra_addr;
    char *device_id = NULL;
    char *rank;

    memset(device_id_prefix, 0, 50);

    device_id = an_get_device_id();

    if (!device_id) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE,NULL,
                "\nDevice ID not found");
        return;
    }

    an_strncpy_s(device_id_prefix, strlen(device_id), device_id,
            strlen(device_id));

    rank = an_strchr(device_id_prefix, AN_HOSTNAME_SUFFIX_DELIMITER);
    if (!rank) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_SEVERE,NULL,
                "\nError no  prefix found");
        return;
    }

    rank = rank + 1;

    system("sunshine -K");
/*
    if (an_external_anra_is_configured()) {
        memset(&external_ra_addr, 0, sizeof(an_addr_t));
        an_addr_set_from_v6addr(&external_ra_addr, an_external_anra_get_ip());
        external_ra = an_addr_get_string(&external_ra_addr);
        an_sprintf(cmd, "sunshine --dagid rpl instanceid 1 "
            "--dao-if-filter snbi-fe --dao-if-filter snbi-ra --ignore-pio "
            "--dao-addr-filter fd08::/16 --dao-addr-filter %s/128 "
            "--dag-if-filter snbi_tun_* "
            "-p fd08::/16 -p %s/128 --syslog --stderr --verbose "
            "--rank %s > /tmp/rpl.log 2>&1 &", external_ra, external_ra, rank);
    } else {
        an_sprintf(cmd, "sunshine --dagid rpl instanceid 1 "
            "--dao-if-filter snbi-fe --ignore-pio "
            "--dao-addr-filter fd08::/16 --dag-if-filter snbi_tun_* "
            "-p fd08::/16 --syslog --stderr --verbose "
            "--rank %s > /tmp/rpl.log 2>&1 &", rank);
    }
*/
        an_sprintf(cmd, "sunshine --dagid rpl instanceid 1 "
            "--dao-if-filter snbi-* --ignore-pio "
            "--dao-addr-filter fd00::/8 --dag-if-filter snbi_tun_* "
            "-p fd00::/8 --syslog --stderr --verbose "
            "--rank %s --interval 40000 > /tmp/rpl.log 2>&1 &", rank);
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
            "\n%sRPL Execs: \n\t%s \n\t%s", an_bs_event,
            "sysctl -w net.ipv6.conf.all.forwarding=1", cmd);

    system("sysctl -w net.ipv6.conf.all.forwarding=1");
    system(cmd);
}

void an_rpl_global_disable(uint8 *tag_name)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void an_rpl_interface_enable(uint8 *tag_name, ulong ifhndl)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void an_rpl_interface_disable(uint8 *tag_name, ulong ifhndl)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void
an_set_rpl_routing_info (void)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void
an_acp_routing_init (void)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void
an_acp_routing_uninit (void)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void
an_acp_routing_enable (an_routing_cfg_t routing_info)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void
an_acp_routing_enable_on_interface (an_if_t ifhndl,
                                    an_routing_cfg_t routing_info)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void
an_acp_routing_disable_on_interface (an_if_t ifhndl,
                                     an_routing_cfg_t routing_info)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

void
an_acp_routing_disable (an_routing_cfg_t routing_info)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

