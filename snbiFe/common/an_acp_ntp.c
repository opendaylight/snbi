/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include "an_acp_ntp.h"

void
an_acp_ntp_nbr_link_cleanup (an_nbr_link_spec_t *nbr_link_data)
{
    return;
}

void
an_acp_ntp_anr_locally_up_event (void)
{
    return;
}

void
an_acp_ntp_anr_shut_event (void)
{
    return;
}


void
an_acp_ntp_start_clock_sync_nbr (an_nbr_t *nbr)
{
   return;
}
void
an_acp_remove_clock_sync_with_nbr (an_nbr_t *nbr)
{
    return;
}

boolean
an_acp_enable_clock_sync_with_nbr (an_nbr_t *nbr)
{
    return FALSE;
}

void
an_acp_ntp_peer_remove_global(an_nbr_t *nbr)
{
    return;
}

void
an_acp_start_ntp_with_ra (an_addr_t address)
{
    return;
}

void
an_acp_start_ntp_with_nbrs (void)
{
    return;
}

void
an_acp_enable_clock_sync_with_ra (an_addr_t address)
{
    return;
}
