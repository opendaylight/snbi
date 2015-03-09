/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "an_acp_cnp.h"
an_acp_cap_set_t an_acp_capability_set;
boolean an_set_secure_channel_cli = FALSE;

void 
an_acp_negotiate_secure_channel_per_nbr_link (an_nbr_t *nbr,
                                                  an_nbr_link_spec_t *nbr_link_data)
{
    if (!nbr || !nbr_link_data)
    {
        return;
    }
    nbr_link_data->acp_info.sec_channel_negotiated = AN_ACP_IPSEC_ON_GRE;
    nbr_link_data->acp_info.acp_secure_channel_negotiation_started = 0;
    an_acp_create_per_nbr_link(nbr, nbr_link_data);
    nbr_link_data->acp_info.created_time = an_unix_time_get_current_timestamp();
}

boolean 
an_acp_cnp_init (void)
{
    return(TRUE);
}

void 
an_acp_set_default_cap_set (uint16_t param_id)
{
    return;
}

boolean 
an_acp_cnp_uninit (void)
{
    return(FALSE);
}

boolean
an_acp_cnp_is_vrf_applicable (void) 
{
    /* VRF is not applicable in LINUX */
    return (FALSE);
}

void
an_cnp_uninit (void)
{
    return;
}

void
an_cnp_init (void)
{
    return;
}

void
an_cnp_receive_pak (an_msg_package *message_pk)
{
    return;
}
