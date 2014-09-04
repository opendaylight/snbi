/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_TYPES_H__
#define __AN_TYPES_H__

/* AN IOS uses xos for available functionality and ios fucntionality for the
   rest. makesubsys to include the following for AN subsys
   comp_autonomic-networking_an.o  --- for common AN code
   comp_autonomic-networking_xos   --- for xos implemntation of platform 
                                       specific AN code
   comp_autonomic-networking_ios   --- for ios functionality for which xos 
                                       implementation is not available 
 */
//#ifndef AN_IOS
//#define AN_IOS
//#endif /* AN_IOS */  

/* AN Dummy defines dummy platform to ensure common AN code has no platform 
  dependencies*/
//#ifndef AN_DUMMY
//#define AN_DUMMY
//#endif /* AN_DUMMY */ 

/* AN Native IOS uses only native ios functionality.
   makesubsys to include the following for AN subsys
   comp_autonomic-networking_an.o       --- for common AN code
   comp_autonomic-networking_ios  &
   comp_autonomic-networking_native-ios --- for ios functionality of platform 
                                            specific AN code
 */
//#ifndef AN_NATIVE_IOS
//#define AN_NATIVE_IOS
//#endif /* AN_NATIVE_IOS */

//#if defined(AN_DUMMY)
#include "an_types_linux.h"
//#elif defined(AN_IOS)
// #include "../dummy_linux/an_types_ios.h"
// #include "../xos/an_types_xos.h"
//#elif defined(AN_NATIVE_IOS)
//#include "../dummy_linux/an_types_ios.h"
//#include "../native-ios/an_types_native.h"
//#endif

typedef struct an_mem_elem_t_ {
    an_avl_node_t avlnode;
    uint8_t name[50];
    void *buffer;
    uint32_t buffer_size;
} an_mem_elem_t;

typedef struct an_udp_hdr_t_ {
    uint16_t source_port;         /* source port */
    uint16_t dest_port;           /* destination port */
    uint16_t length;              /* bytes in data area */
    uint16_t checksum;            /* checksum */
    uint8_t udpdata[0];           /* start of UDP data bytes */
} an_udp_hdr_t;

typedef struct an_buffer_t_ {
    uint8_t *data;
    uint16_t len;
} an_buffer_t;

typedef struct an_udi_t_ {
    uint8_t *data;
    uint16_t len;
} an_udi_t;

typedef struct an_cert_t_ {
    uint8_t *data;
    uint16_t len;
} an_cert_t;

typedef struct an_cert_req_t_ {
    uint8_t *data;
    uint16_t len;
} an_cert_req_t;

typedef struct an_key_t_ {
    uint8_t *data;
    uint16_t len;
} an_key_t;

typedef struct an_payload_t_ {
    uint8_t *data;
    uint16_t len;
} an_payload_t;

typedef struct an_network_prefix_t_ {
    an_addr_t addr;
    uint8_t len;
} an_network_prefix_t;

typedef struct an_routing_cfg_t_ {
    uint16_t ospf_pid;
    uint16_t ospf_area;
    uint32_t ospf_rid;
    an_rpl_info_t an_rpl_info;
} an_routing_cfg_t;

typedef struct an_ipv6_nd_opt_hdr_ {
        uint8_t type;
            uint8_t len;
} an_ipv6_nd_opt_hdr;

typedef struct an_ipv6_nd_opt_ {
    uint8_t type;
    uint8_t length;     /* in uints of 8 octets */
    uint8_t padd[2];    /* To align value with word boundary */
    uint8_t value[0];
} an_ipv6_nd_opt;

typedef struct an_aaa_param_ {
    an_addr_t address;
    uint32_t auth_port;
    uint32_t acct_port;
    uint8_t *secret_key;
    an_if_t source_if_num;
} an_aaa_param_t;

typedef struct an_ntp_peer_param_ {
    an_addr_t peer_addr;
    uint8_t *hostname;
    uint32_t auth_key;
    uint32_t mode;
    an_if_t ifhdl;
} an_ntp_peer_param_t;

typedef struct an_info_t_ {
    an_udi_t udi;
    an_cert_t domain_cert;
    uint8_t *device_id;
    uint8_t *domain_id;
    an_addr_t device_ip;
    an_cert_t anra_cert;
    an_addr_t anra_ip;
    an_routing_cfg_t routing;
    an_if_t anra_ifhndl;
    an_iptable_t iptable;
    an_afi_t afi;
    an_addr_t aaa_ip;
    an_addr_t nms_ip;
} an_info_t;

#endif
