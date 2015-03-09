/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_IPV6_ND_H__
#define __AN_IPV6_ND_H__

#include "an_types.h"

boolean an_ipv6_nd_attach(void); 
boolean an_ipv6_nd_detach(void);
void an_ipv6_nd_trigger_unsolicited_na (an_v6addr_t *v6addr, an_if_t ifhdl);

#endif
