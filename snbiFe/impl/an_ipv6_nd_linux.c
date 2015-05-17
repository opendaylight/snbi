/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_nd.h>
#include <an_msg_mgr.h>
#include <an_ipv6_nd.h>

boolean
an_ipv6_nd_attach (void)
{
    return (FALSE);
}

boolean
an_ipv6_nd_detach (void)
{
    return (FALSE);
}

void
an_ipv6_nd_trigger_unsolicited_na (an_v6addr_t *v6addr, an_if_t ifhndl)
{
    printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}
