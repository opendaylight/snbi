/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_IPV6_SEND_H__
#define __AN_IPV6_SEND_H__

#include "an_types.h"

#define AN_IPV6_SEND_SEC_LEVEL 1
#define AN_IPV6_SEND_ITERATIONS 0 

void 
an_ipv6_send_init(const uint8_t* label, uint8_t sec_level, uint32_t max_iter);
void an_ipv6_send_uninit(const uint8_t* label);
inline void 
an_ipv6_send_init_on_interface(an_if_t ifhndl, const uint8_t *label);
inline void
an_ipv6_send_init_on_interface_with_secmode_transit(an_if_t ifhndl, const uint8_t *label);
inline void 
an_ipv6_send_uninit_on_interface(an_if_t ifhndl, const uint8_t *label);
//inline void
//an_ipv6_send_change_nd_mode(an_if_t ifhndl, an_ipv6_SEND_secmode_type secmode_type);
#endif
