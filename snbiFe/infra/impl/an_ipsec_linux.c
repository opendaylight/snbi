/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_ipsec.h>
#include <an_ike.h>
#include <an_logger.h>


uint8_t an_ipsec_profile_name[AN_IPSEC_PROFILE_NAME_BUF_SIZE] = {};
uint32_t an_ipsec_profile_id = AN_IPSEC_PROFILE_NUM_START;

void
an_ipsec_define_profile_name (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}

void 
an_ipsec_profile_init (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}

void 
an_ipsec_profile_uninit (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}
boolean 
an_ipsec_apply_on_tunnel (an_if_t tunn_ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return FALSE;
}

void
an_ipsec_remove_on_tunnel (an_if_t tunn_ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}
