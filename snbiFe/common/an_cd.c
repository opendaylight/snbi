/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include "an_cd.h"

boolean
an_cd_intf_set_state (an_if_t ifhndl, an_cd_intf_state_e state)
{
	return (TRUE);
}

boolean
an_cd_stop_punt (an_mac_addr *macaddress,
        ulong ether_type, an_if_t ifhndl)
{
	return (TRUE);
}

boolean
an_cd_does_channel_exist_to_nbr (an_msg_package *message)
{
	return (FALSE);
}

boolean
an_cd_init (void)
{
    return (TRUE);
}

boolean
an_cd_uninit (void)
{
    return (TRUE);
}
void 
an_cd_register_for_events (void)
{
    return;
}

boolean an_cd_start_punt(an_mac_addr *macaddress, ulong ether_type,
        an_if_t ifhndl)
{
    return (FALSE);
}

void
an_cd_init_cd_if_info (an_if_t ifhndl)
{
    return;
}
