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
#if 0
#ifndef AN_NATIVE_IOS
#define AN_NATIVE_IOS
#endif /* AN_NATIVE_IOS */
#endif

#ifndef AN_LINUX
#define AN_LINUX
#endif /* AN_NATIVE_IOS */

#if defined(AN_DUMMY)
#include "../dummy/an_types_dummy.h"
#elif defined(AN_IOS)
#include "../ios/an_types_ios.h"
#include "../xos/an_types_xos.h"
#elif defined(AN_NATIVE_IOS)
#include "../ios/an_types_ios.h"
#include "../native-ios/an_types_native.h"
#elif defined(AN_IOSXR)
#include "../xr/include/an_types_xr.h"
#elif defined(AN_LINUX)
#include "../infra/impl/an_types_linux.h"
#endif

#define AN_HOSTSIZE 256
#define AN_LABELSIZE 64

void an_buginf(const char *fmt, ...);

extern boolean global_ike_cli_executed_by_an;

#if 0
typedef enum an_service_type_t_ {

    AN_AAA_SERVICE,
    AN_SYSLOG_SERVICE,
    AN_ANR_SERVICE,
    AN_MAX_SERVICE,

} an_service_type_t;
#endif

typedef enum an_cert_validation_result_e_ {
    AN_CERT_VALIDITY_UNKNOWN = 0,
    AN_CERT_VALIDITY_PASSED,
    AN_CERT_VALIDITY_PASSED_WARNING,
    AN_CERT_VALIDITY_FAILED,
    AN_CERT_VALIDITY_EXPIRED,
    AN_CERT_VALIDITY_REVOKED,
    AN_CERT_VALIDITY_PENDING,
    AN_CERT_VALIDITY_BUSY_CRL_POLL,
} an_cert_validation_result_e;

typedef enum an_cert_revocation_e_ {
   AN_CERT_REVOCATION_UNKNOWN = 0,
   AN_CERT_REVOCATION_VALID,
   AN_CERT_REVOCATION_INVALID,
} an_cert_revocation_e;

typedef enum an_cert_life_e_ {
    AN_CERT_LIFE_UNKNOWN = 0,
    AN_CERT_LIFE_VALID,
    AN_CERT_LIFE_EXPIRED,
} an_cert_life_e;

typedef struct an_l2_info_t_ {
    uint32_t outer_vlan_id;
    uint32_t inner_vlan_id;
} an_l2_info_t;

typedef struct an_cert_validation_t_ {
    boolean common_trust_anchor;
    an_cert_validation_result_e result;
    an_cert_revocation_e revocation_status;
    an_cert_life_e life;
} an_cert_validation_t;

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
    boolean valid;
    an_unix_time_t expired_time;
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

typedef struct an_ipv6_nd_opt_hdr_t_ {
	uint8_t type;
	uint8_t len;
} an_ipv6_nd_opt_hdr;

typedef struct an_ipv6_nd_opt_t_ {
    uint8_t type;
    uint8_t length;     /* in uints of 8 octets */
    uint8_t padd[2];    /* To align value with word boundary */
    uint8_t value[0];
} an_ipv6_nd_opt;

typedef struct an_aaa_param_t_ {
    an_addr_t address;
    uint32_t auth_port;
    uint32_t acct_port;
    uint8_t *secret_key;
    an_if_t source_if_num;
} an_aaa_param_t;

typedef struct an_config_param_t_ {
    an_addr_t address;
    uint8_t *directory;
} an_config_param_t;

typedef struct an_anr_param_t_ {
    an_addr_t address;
    uint8_t *ca_type;
} an_anr_param_t;

typedef struct an_ntp_peer_param_t_ {
    an_addr_t peer_addr;
    uint8_t *hostname;
    uint32_t auth_key;
    uint32_t mode;
    uint8_t *vrfname;
    an_if_t ifhdl;
} an_ntp_peer_param_t;

typedef struct an_info_t_ {
    an_udi_t udi;
    an_cert_t domain_cert;
    uint8_t *device_id;
    uint8_t *domain_id;
    an_addr_t device_ip;
    an_cert_t ca_cert;
    an_addr_t anra_ip;
    an_routing_cfg_t routing;
    an_if_t anra_ifhndl;
    an_iptable_t iptable;
    an_afi_t afi;
    an_addr_t aaa_ip;
    an_addr_t nms_ip;
    an_mac_addr *anra_mac;
    an_addr_t cert_renewal_anr_ip;
} an_info_t;

typedef struct an_cnp_capability_t_ {
    uint8_t *data;
    uint16_t len;
} an_cnp_capability_t;

typedef struct an_cnp_cap_error_t_ {
    uint8_t *data;
    uint16_t len;
} an_cnp_cap_error_t;

extern uint8_t an_multicast[6];

#if 0
typedef struct an_address_saved_context_t_ {
    an_service_type_t an_service_type;
    an_addr_t address;
    uint8_t sername[AN_HOSTSIZE];
    uint8_t regtype[AN_LABELSIZE];
    uint8_t domain[AN_LABELSIZE];
    ulong if_index;
} an_address_saved_context_t;

typedef struct an_aaa_saved_context_t_ {
    an_service_type_t an_service_type;
    an_addr_t address;
    uint32_t auth_port;
    uint32_t acct_port;
    uint8_t secret_key[AN_AAA_SECRET_KEY_LENGTH];
    an_if_t source_if_num;
} an_aaa_saved_context_t;
#endif

#endif
