/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_DIKE_H__
#define __AN_DIKE_H__

boolean an_dike_profile_apply_on_tunnel(an_if_t tunn_ifhndl, 
                    uint16_t ll_dike_port, uint16_t remote_dike_port);
void an_dike_profile_remove_on_tunnel(an_if_t tunn_ifhndl);
#endif


