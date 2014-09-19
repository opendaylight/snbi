/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_L2_LINUX_H__
#define __AN_L2_LINUX_H__

#include "an_if_mgr.h"

#define AN_VLAN_START     2000
#define AN_NO_INNER_VLAN_TAG 0
#define AN_TEMP_INNER_TAG 4094
#define AN_MAX_WAIT_COUNT_BEFORE_SETUP_ABORT 10

boolean an_l2_enable_channel(an_if_t ifhndl, an_cd_info_t *);
void an_disable_switchport_on_if(an_if_t ifhndl);
an_if_t an_configure_vti_for_l2_port(an_if_t phy_an_if);
#endif
