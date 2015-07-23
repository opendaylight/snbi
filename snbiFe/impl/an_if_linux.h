/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_IF_LINUX_H__
#define __AN_IF_LINUX_H__

#include <olibc_if.h>
#include <an_types.h>

#define AN_IF_NAME_LEN OLIBC_MAX_IF_NAME_LEN
#define AN_IF_HW_ADDR_LEN OLIBC_MAX_IF_HW_ADDR_LEN

typedef struct an_if_linux_info_t_ {
    char if_name[AN_IF_NAME_LEN];
    uint32_t if_index;
    olibc_if_state_e if_state;
    boolean is_loopback;
    uint8_t hw_addr[AN_IF_HW_ADDR_LEN];
    uint32_t hw_addr_len;
    uint32_t hw_type;
} an_if_linux_info_t;

typedef struct linux_dot1q_qinq_vlan_id_t_ {
    ushort vlanid; /* This is the Outer/only VLAN Id */
    ushort inner_vlanid;
} linux_dot1q_qinq_vlan_id_t;
boolean an_if_is_acp_interface(an_if_t an_ifhndl);

extern void an_if_enable_nd_on_all_intfs(void);
#endif
