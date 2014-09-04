/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_types.h"
#include "an_if.h"
#include "an_tunnel.h"
#include "an_addr.h"
#include "an_mem.h"
#include "an_ipv6.h"
#include "an_syslog.h"
#include "an_acp.h"
#include "an_logger.h"
const struct message_  *an_syslog_msg_p[MAX_AN_SYSLOG_MSG_TYPE];

an_addr_t *hstaddran = NULL;

void 
an_syslog_init (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
            return;
}

void 
an_syslog (an_syslog_msg_e type,...)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
            return;
}

void 
an_syslog_config_host (an_addr_t *hstaddran, char *an_vrf_name,
                       an_idbtype *an_idb, char *discriminator)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
            return;
}

void
an_syslog_delete_host (an_addr_t *hstaddran, char *an_vrf_name)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
            return;
}

int
an_logger_discriminator (char* discriminator, ushort fac_includes_drops_flag,
                         char* facility_name, ushort sev_includes_drops_flag,
                         char* new_sev_group, boolean add)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

void 
an_syslog_create_an_discriminator (void) {
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}
