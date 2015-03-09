/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_IPSEC_H__
#define __AN_IPSEC_H__

#define AN_IPSEC_PROFILE_NUM_START 0
#define AN_IPSEC_PROFILE_NUM_END 2147483647

#define AN_IPSEC_PROFILE_NAME_BUF_SIZE 32 
#define AN_IPSEC_PROFILE_NAME "CISCO_AN_IPSEC_PROFILE"

extern uint8_t an_ipsec_profile_name[AN_IPSEC_PROFILE_NAME_BUF_SIZE];
extern uint32_t an_ipsec_profile_id;

//IPSec
void an_ipsec_define_profile_name(void);
void an_ipsec_set_profile_name(uint32_t unit);
void an_ipsec_clear_profile_name(void);
void an_ipsec_profile_init(void);
void an_ipsec_profile_uninit(void);
//void an_ipsec_apply_on_tunnel(an_idbtype *tunnel_idb);
//void an_ipsec_remove_on_tunnel(an_idbtype *tunnel_idb);
boolean an_ipsec_apply_on_tunnel(an_if_t tunn_ifhndl);
void an_ipsec_remove_on_tunnel(an_if_t tunn_ifhndl);
#endif
