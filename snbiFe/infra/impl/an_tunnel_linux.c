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

an_vrf_info_t an_vrf_info;


an_if_t 
an_tunnel_create (an_addr_t *src, an_addr_t *dst, an_if_t src_if, uint8_t mode)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (0);
}

void an_tunnel_remove (an_if_t ifhndl) 
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}
        
boolean 
an_vrf_unconfigure_interface (an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return TRUE;
}

boolean 
an_vrf_configure_interface (an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return TRUE;
}
        
boolean 
an_vrf_define (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return FALSE;
}

void
an_vrf_remove (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}

void an_vrf_set_id (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}

void
an_tunnel_init (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}

void
an_tunnel_uninit (void) 
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}

void an_tunnel_check_integrity (an_if_t tunn_ifhndl, an_if_t tunn_src_ifhndl)
{
}

