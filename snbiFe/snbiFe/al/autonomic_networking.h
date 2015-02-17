/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AUTONOMIC_NETWORKING_H__ 
#define __AUTONOMIC_NETWORKING_H__

#include "../al/an_types.h"


/* 
 * If the packet is double tagged, the channel discovery
 * packet would contain both the tags.
 */
#if 0
typedef struct an_l2_info_t_ {

    uint32_t outer_vlan_id;
    uint32_t inner_vlan_id;

} an_l2_info_t;
#endif
/**
  * an_enqueue_l2_pkt
  *
  * API to get the L2 packet whose destination address is AN 
  * Multicast MAC 
  * address.
  *
  * @param[in] an_pak - Pointer to the Incoming packet
  * @param[in] an_l2_info - Pointer to an_l2_info_structure.
  *                         The memory for the same is owned 
  *                         by the driver (calling process)
  *
  * @param[out] void 
  *
  * @retval - TRUE/FALSE
  *     Returns TRUE when the packet has been consumed by the
  * autonomic networking process. Else the driver
  * needs to handle the packet further.
  *
  * @usage
  *     This is to inform AN process of an incoming AN packet. 
  * The destination multicast MAC address is expected to 
  * be 01-44-11-11-11-11.
  *
  * @safety #ThreadSafe
  *
  * @note #MemUsage
  * The packet will be freed by the AN process after handling the same.
  */
boolean
an_enqueue_l2_pkt (an_pak_t *an_pak, an_l2_info_t *l2_info);

/**
  * is_device_autonomic 
  *
  * API to check if the device is running in autonomic mode.
  *
  * @param[in] None
  *
  * @retval boolean - TRUE, if device is running in autonomic mode.
  *
  * @usage
  *     At any point of time if the applications want to check 
  * if the device is running in autonomic mode.
  *
  * @safety #ThreadSafe
  *
  * @note #MemUsage
  *  Also see is_int_autonomic()
  */
boolean
is_device_autonomic (void);

/**
  * is_int_autonomic 
  *
  * API to check if specific interface is in autonomic mode.
  *
  * @param[in] an_if_t - Handle to the interface
  *
  * @retval boolean - TRUE, if interface is running in autonomic mode.
  *
  * @usage
  *     At any point of time if the applications want to 
  * check if the given interface is running in autonomic mode.
  *
  * @safety #ThreadSafe
  *
  * @note #MemUsage
  *    The an_if_t(Handle) can be obtained using the 
  *    following API from the swidb in IOS.
  *          an_if_t = idb_get_if_number(swidb);
  *   
  *  Also see is_device_autonomic().
  */
boolean
is_int_autonomic (an_if_t an_if);

#endif 
