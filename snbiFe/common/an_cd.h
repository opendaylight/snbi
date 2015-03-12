/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_CD_H__
#define __AN_CD_H__

#include "../al/an_types.h"
#include "an_msg_mgr.h"

typedef enum an_cd_intf_state_e_ {
    AN_CD_INTF_STATE_UP  = 0, 
    AN_CD_INTF_STATE_DOWN,  
} an_cd_intf_state_e;

#define AN_CD_IEEE_ETHERTYPE 0x0

boolean an_cd_stop_punt(an_mac_addr *macaddress,
        ulong ether_type, an_if_t ifhndl);

boolean
an_cd_does_channel_exist_to_nbr(an_msg_package *message);
boolean an_cd_init(void);
boolean an_cd_uninit(void);
void an_cd_register_for_events(void);
boolean an_cd_start_punt(an_mac_addr *macaddress, ulong ether_type,
        an_if_t ifhndl);
void
an_cd_init_cd_if_info(an_if_t ifhndl);
#endif
