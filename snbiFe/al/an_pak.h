/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_PAK_AL_H__
#define __AN_PAK_AL_H__

#include "an_types.h"

inline uint8_t* an_pak_get_network_hdr(an_pak_t *pak);
inline uint8_t* an_pak_get_datagram_hdr(an_pak_t *pak);
inline uint8_t* an_pak_get_transport_hdr(an_pak_t *pak);
inline an_if_t an_pak_get_input_if(an_pak_t *pak);
inline an_if_t an_pak_get_output_if(an_pak_t *pak);
inline const uint8_t* an_pak_get_input_if_name(an_pak_t *pak);
inline const uint8_t* an_pak_get_output_if_name(an_pak_t *pak);
inline an_iptable_t an_pak_get_iptable(an_pak_t *pak);
inline void an_pak_set_output_if(an_pak_t *pak, an_if_t output_if);
inline void an_pak_set_input_if(an_pak_t *pak, an_if_t input_if);
inline void an_pak_set_iptable(an_pak_t *pak, an_iptable_t iptable);
inline void an_pak_set_datagram_size(an_pak_t *pak, uint16_t paklen);
inline void an_pak_set_linktype(an_pak_t *pak, uint8_t linktype);
inline uint8_t an_pak_get_linktype(an_pak_t *pak);

an_pak_t * an_getbuffer (uint16_t pak_len);
an_pak_t* an_pak_alloc(uint16_t pak_len);
inline void an_pak_free(an_pak_t *pak);
boolean an_pak_grow(an_pak_t **pak, uint16_t resize_len);
an_pak_t* an_pak_duplicate(an_pak_t *pak);
void an_enqueue_pkt(an_pak_t *pak);
inline size_t an_pak_subblock_getsize(an_pak_subblock_index_t idx);
void an_pak_subblock_setsize(an_pak_subblock_index_t idx, size_t size);
inline boolean an_linktype_is_an(uint8_t linktype);
void an_handle_l2_pak(an_pak_t *pak);

#endif
