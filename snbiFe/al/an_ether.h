/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_ETHER_H__
#define __AN_ETHER_H__

#include "an_types.h"
#include "../common/an_cd.h"

inline uint8_t *an_ether_hdr_get_src(an_ether_hdr_t *ether_hdr);
inline uint8_t *an_ether_hdr_get_dest(an_ether_hdr_t *ether_hdr);
inline void an_ether_addr_zero(an_mac_addr * mac_addr);
inline void an_ether_addr_copy(uint8_t *from, uint8_t *to);
inline ushort an_get_cd_vlanid(an_cd_info_t *an_cd_info);

inline boolean an_ether_is_addr_zero(an_mac_addr * mac_addr);

inline ushort an_get_cd_vlanid(an_cd_info_t *an_cd_info);
inline ushort an_get_cd_inner_vlanid(an_cd_info_t *an_cd_info);

#endif
