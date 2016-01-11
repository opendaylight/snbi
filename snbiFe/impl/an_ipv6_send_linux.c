/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_nd.h>
#include <an_addr.h>
#include <an_ipv6.h>
#include <an_ipv6_send.h>


extern const an_v6addr_t an_linklocal_prefix;

void an_ipv6_send_init (const uint8_t* label, uint8_t sec_level, 
                        uint32_t max_iter)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

void an_ipv6_send_uninit (const uint8_t *label)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

inline void an_ipv6_send_init_on_interface (an_if_t ifhndl, 
                                             const uint8_t *label)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

inline void an_ipv6_send_init_on_interface_with_secmode_transit (an_if_t ifhndl,
                                             const uint8_t *label)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

inline void an_ipv6_send_uninit_on_interface (an_if_t ifhndl, 
                                            const uint8_t *label)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

//inline void
//an_ipv6_send_change_nd_mode (an_if_t ifhndl, an_ipv6_SEND_secmode_type secmode_type)
//{
    //ipv6_SEND_intf_set_secmode(ifhndl, secmode_type);

//}

