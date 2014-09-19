/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_TUNNEL_H__
#define __AN_TUNNEL_H__

#include "an_types.h"

#define AN_TUNNEL_NUM_START 100000
#define AN_TUNNEL_NUM_END 2147483647

an_if_t an_tunnel_create(an_addr_t *src, an_addr_t *dst, an_if_t src_if, uint8_t tunn_mode);
void an_tunnel_remove(an_if_t tunn_ifhndl);

void an_tunnel_init(void);
void an_tunnel_uninit(void);
#endif
