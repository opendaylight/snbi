/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_IF_LINUX_H__
#define __AN_IF_LINUX_H__

#include <an_types.h>

typedef struct linux_dot1q_qinq_vlan_id_t_ {
    ushort vlanid; /* This is the Outer/only VLAN Id */
    ushort inner_vlanid;
} linux_dot1q_qinq_vlan_id_t;
boolean an_if_is_acp_interface(an_if_t an_ifhndl);
#endif
