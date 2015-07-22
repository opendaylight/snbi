/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_service_discovery_linux.h>
#include <an_ipv6.h>
#include <an_addr.h>
#include <an_syslog.h>
#include <an_aaa.h>
#include <an_mem.h>
#include <an_event_mgr.h>
#include <an_acp.h>
#if 0
typedef enum an_service_type_t_ {

    AN_AAA_SERVICE,
    AN_SYSLOG_SERVICE,
    AN_MAX_SERVICE,

} an_service_type_t;
#endif

extern an_aaa_param_t    aaa_sd_param_global;
an_mem_chunkpool_t *an_aaa_saved_context_pool = NULL;
an_mem_chunkpool_t *an_address_saved_context_pool = NULL;
#if 0
typedef struct an_ctx_info_t_ {

     an_service_type_t an_service_type;
     void *service_param;

} an_ctx_info_t;
#endif

//an_ctx_info_t an_ctx_info[AN_MAX_SERVICE];

an_addr_t  syslog_sd_param_global;

void
an_service_clear_entry (an_service_type_t an_service_type)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_sd_aaa_get_parse_data (an_aaa_param_t *aaa_sd_param_local,
                          char *parse_string)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}

void
an_discover_services (an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

/*
 * an_service_ref_deallocate
 * Remove the sdRef allocation in mdns
 *
 * Input: Type of sdRef
 * Output:Null
 * Return: void
 */
void  
an_discover_services_deallocate (an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void 
an_sd_cfg_global_commands (boolean set) 
{
    return;
}

void 
an_clear_service_info_db (void) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void 
an_mdns_anra_service_add (an_addr_t anra_ip, an_if_t int_index, uint8_t *l2_mac) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

uint32_t an_rand(void)
{
        return (0);
}

void
an_discover_services_stop(an_if_t ifhndl) {
        an_discover_services_deallocate(ifhndl);
}

void
an_DNSServiceRefDeallocate (an_DNSServiceRef serviceRef)
{
}

void
an_mdns_io_set_rate_limit_rate (uint32_t packet_num)
{
}

void
an_host_resolve (an_srvc_host_t *host_data, an_if_t ifIndex)
{
}

boolean
an_service_withdraw (an_service_type_t service_type, uint8_t *serName,
                    an_if_t int_index)
{
        return (TRUE);
}

boolean
an_service_announce (an_service_type_t service_type, uint8_t *serName,
                        an_addr_t service_ip, void *service_param, an_if_t
                        int_index)
{
    return TRUE;
}

void
an_service_resolve (uint8_t *serName, uint8_t *regType, uint8_t *domain,
                                an_srvc_srv_t *srv_data)
{
        return;
}

void
an_service_reflect_on_interfaces (an_srvc_srv_ctx_t *saved_context)
{
}

