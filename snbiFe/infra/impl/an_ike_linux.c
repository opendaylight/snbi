/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_ike.h>
#include <an_logger.h>
#include <an.h>


char an_ikev2_proposal_name[AN_IKEV2_PROPOSAL_NAME_BUF_SIZE] = {'\0'};
char an_ikev2_policy_name[AN_IKEV2_POLICY_NAME_BUF_SIZE] = {'\0'};
char an_ikev2_key_name[AN_IKEV2_KEY_NAME_BUF_SIZE] = {'\0'};
char an_ikev2_profile_name[AN_IKEV2_PROFILE_NAME_BUF_SIZE] = {'\0'};
boolean global_ike_cli_executed_by_an = FALSE;

void
an_ikev2_profile_init (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void
an_ikev2_profile_uninit (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

