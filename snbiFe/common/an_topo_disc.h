/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __TOPOLOGY_DISCOVERY__PROTO_H__
#define __TOPOLOGY_DISCOVERY__PROTO_H__

extern char *global_url_str;
#if 0
#include "../al/an_addr.h"
#include "an_nbr_db.h"
#include "../al/an_ipv6.h"
#include "../al/an_if.h"

#include "an_topology_discovery.h"
#include "../shim/an/loc_shims/an_topology_discovery_shim.h" 

#define TDP_IPV6_VERSION 6
#define TDP_IPV6_HDR_SIZE sizeof(an_ipv6_hdr_t)
#define TDP_PROT 181
#define TDP_DEFAULT_HOP_LIMIT 255
#define TDP_DEFAULT_TOS 0
#define TDP_DEFAULT_FLOW_LABEL 0

#define TOPO_DISC_MSG_LEN 255

typedef enum topo_msg_t_ {
    TOPO_REQ,
    TOPO_RESP,
    TOPO_MAX
} topo_msg_t;

#define TOPO_DEVICE_ID_LEN 26

typedef struct topo_message_ {

    topo_msg_t  msg_type;

    /*
     * Topology Request ID, which is expected to be unique for
     * every request. After 300 seconds, this ID expires.
     * This ID could be the timestamp, this also requires
     * all the devices are under the same clock.
     */
    time_t       topo_request_id;

    /*
     * The intiator address is used by all entities recieving
     * the topology request message for the "topology response".
     */
    an_v6addr_t initiator_addr;

} topo_message;

#define TOPO_RESP_MSG_LEN   160

#define LOCAL_NODE_NAME_LEN 26
#define LOCAL_PORT_NAME_LEN 26
#define PEER_PORT_NAME_LEN 26
#define PEER_NODE_NAME_LEN 26

typedef struct topo_resp_message_ {

    topo_msg_t   msg_type;
    time_t       topo_request_id;
    an_topo_event_t topo_event;

    char         peer_node[PEER_NODE_NAME_LEN];
    char         peer_port[PEER_PORT_NAME_LEN];
    char         local_node[LOCAL_NODE_NAME_LEN];
    char         local_port[LOCAL_PORT_NAME_LEN];

} topo_resp_message;

typedef struct topo_call_back_param_ {

    time_t      topo_request_id;
    an_if_t     ifhndl;
    an_v6addr_t initiator_addr;

} topo_call_back_param;

void topo_disc_init(void);
void topo_disc_uninit(void);
void topo_disc_initiate(void);
void topo_disc_adv(void);
void topo_nbr_disconnect(an_nbr_t *nbr);
void topo_nbr_connect(an_nbr_t *nbr);
void topo_nbr_update(an_nbr_t *nbr, an_topo_event_t topo_event);
void an_notify_masa_application(char *str);
#endif
#endif
