/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_IKE_H__
#define __AN_IKE_H__

#define AN_IKEV2_PROPOSAL_NAME "CISCO_AN_IKEV2_PROPOSAL"
#define AN_IKEV2_POLICY_NAME "CISCO_AN_IKEV2_POLICY"
#define AN_IKEV2_KEY_NAME "CISCO_AN_IKEV2_KEY"
#define AN_IKEV2_PROFILE_NAME "CISCO_AN_IKEV2_PROFILE"

#define AN_IKEV2_PROPOSAL_NAME_BUF_SIZE 32 
#define AN_IKEV2_POLICY_NAME_BUF_SIZE 32 
#define AN_IKEV2_KEY_NAME_BUF_SIZE 32 
#define AN_IKEV2_PROFILE_NAME_BUF_SIZE 32 


extern char an_ikev2_proposal_name[AN_IKEV2_PROPOSAL_NAME_BUF_SIZE];
extern char an_ikev2_policy_name[AN_IKEV2_POLICY_NAME_BUF_SIZE];
extern char an_ikev2_key_name[AN_IKEV2_KEY_NAME_BUF_SIZE];
extern char an_ikev2_profile_name[AN_IKEV2_PROFILE_NAME_BUF_SIZE];


//IKE
void an_ikev2_define_profile_names(uint32_t unit);
void an_ikev2_clear_profile_names(void);
void an_ikev2_profile_init(void);
void an_ikev2_profile_uninit(void);
char* an_ikev2_get_profile_name(void);
#endif
