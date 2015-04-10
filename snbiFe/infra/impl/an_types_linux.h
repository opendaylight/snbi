/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_TYPES_LINUX_H__
#define __AN_TYPES_LINUX_H__

#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <an_timer_linux.h>
//#include <an_if_linux.h>
#include <an_pak_linux.h>
#include <an_avl_linux.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>

#define AN_UDI_STR_TERMINATOR_LEN 1
#define AN_CERR_SUCCESS 0
#define AN_CERR_FAIL 1
#define AN_CERR_POSIX_ERROR(cer_no) cer_no
#define AN_CERR_V_FATAL(subs, value, posx) 0
#define AN_PAK_SUBBLOCK_L2_INFO 0
#define AN_LINK_IPV6 0
#define AN_WALK_FAIL FALSE
#define AN_WALK_SUCCESS TRUE
#define AN_AVL_WALK_FAIL FALSE
#define EOK TRUE
#define EFAIL FALSE
#define CERR_IS_OK(cer_no)           ((cer_no) == AN_CERR_SUCCESS)
#define AN_CERR_IS_OK(cer_no)           ((cer_no) == AN_CERR_SUCCESS)
#define CERR_IS_NOTOK(cer_no)        (!CERR_IS_OK((cer_no)))
#define AN_CERR_IS_NOTOK(cer_no)        (!CERR_IS_OK((cer_no)))

#define SIGTIMER     (SIGRTMAX)
#define AN_LINUX_ERROR -1

static inline
void buginf (const char *format, ...) 
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

typedef struct an_list_element_ an_list_element;
typedef struct an_list_header_  an_list_header;

struct an_list_header_
{
    void              *lock;

    an_list_element      *head;
    an_list_element      *tail;
    unsigned short     flags;
    unsigned long      count;
    unsigned long      maximum;
    const char *name;
};

struct an_list_element_
{
    an_list_element  *next;
    an_list_element  *prev;
    void          *data;
    an_list_header   *list;
};

typedef struct an_list_element_ an_list_element_t;
typedef struct an_list_header_  an_list_t;


#define LIST_GET_DATA(element) ((element) ? (element)->data : NULL)
#define LIST_HEAD_ELEMENT(list)    (list)->head
#define LIST_NEXT_ELEMENT(element) ((element) ? (element)->next : NULL)

#define LIST_NEXT_DATA(element)      \
    (LIST_NEXT_ELEMENT(element)) ? LIST_NEXT_ELEMENT(element)->data : NULL
#define LIST_HEAD_DATA(list)      \
    (LIST_HEAD_ELEMENT(list)) ? LIST_HEAD_ELEMENT(list)->data : NULL

#define ELEMENT_GET_LIST(element) ((element) ? (element)->list : NULL)

#define AN_FOR_ALL_DATA_IN_LIST(__list, __element, __data) \
  for (__element = LIST_HEAD_ELEMENT(__list),           \
       __data = LIST_GET_DATA(__element);               \
       __element != NULL;                               \
       __element = LIST_NEXT_ELEMENT(__element),        \
       __data = LIST_GET_DATA(__element))

#define AN_FOR_ALL_ELEMENTS_IN_LIST_SAVE_NEXT(__list, __element, __next) \
  for ((__element)  = LIST_HEAD_ELEMENT((__list));                        \
       (__next) = LIST_NEXT_ELEMENT((__element)), (__element) != NULL;      \
       (__element) = (__next))

typedef unsigned int an_dummy_t;
typedef unsigned char uint8_t;
typedef unsigned char uint8;
typedef unsigned char uchar;
typedef unsigned int uint32_t;
typedef unsigned int uint32;
//typedef unsigned int uint;
typedef signed int int32_t;
typedef signed char int8_t;
typedef signed short int16_t;
typedef unsigned short uint16;
typedef unsigned short uint16_t; 
//typedef unsigned short ushort; 
typedef unsigned long ulong; 
//typedef unsigned long long uint64_t; 
typedef long time_t; 
typedef ulong an_thread_t;
typedef bool an_avl_walk_e;
typedef an_dummy_t httpc_session_id_t;
typedef an_dummy_t httpc_api_status_t;
typedef an_dummy_t httpc_res_app_data_t;
typedef an_dummy_t httpc_req_app_data_t;
typedef an_dummy_t httpc_resp_ctxt_t;
typedef an_dummy_t httpc_transaction_id_t;
typedef an_dummy_t httpc_app_req_params_t;
typedef an_dummy_t topo_event_t;
typedef an_list_element_t xos_list_element_t;
typedef bool boolean;
typedef uint32_t an_cerrno;
typedef uint32_t an_errno;
typedef ulong an_rsize;
typedef boolean an_walk_e;
typedef long long longlong;
typedef ulong an_unix_time_t;
typedef longlong an_unix_msec_time_t;
typedef an_dummy_t an_watched_boolean;
typedef an_dummy_t an_cnp_capability_set_t;
typedef an_dummy_t masa_msg_type;
typedef an_dummy_t masa_app_context;
typedef an_dummy_t an_DNSServiceRef;
typedef an_dummy_t an_cd_oper_e;
typedef an_dummy_t an_cd_info_t;
typedef an_dummy_t an_intent_ver_t;
typedef an_dummy_t an_idp_info_t;
//typedef an_dummy_t an_cd_state_e;
typedef uint8_t an_mac_addr;
#define AN_IEEEBYTES 6
#define AN_AVL_WALK_SUCCESS TRUE
#define AN_MACADDR_DELIMITER_DEVICE_NAME '.'
#define AN_MACADDR_DELIMITER_SERVICE_NAME ':'
typedef an_dummy_t an_ifs_pathent;
typedef an_dummy_t an_bitlist_t;
typedef an_dummy_t an_intent_outer_vlans_db_t;
#define AN_INTENT_BITLIST_VLAN_MAX 4096
#define AN_INTENT_BITLIST_VLAN_MIN 0
#define AN_INTENT_BITLIST_VLAN_END -1
#define AN_SERVICE_INSTANCE_START 1
#define AN_CONFIG_PATH_LENGTH 255
#define an_sprintf sprintf

#define TRUE true
#define FALSE false
//#define NULL 0
int printf(const char *fmtptr, ...);
//#define an_buginf printf
#define EINVAL 22
#define TOPO_EVENT_UP 0
#define ADDRLEN_IP 4
#define ADDRLEN_IPV6 16
// #define IPPROTO_ICMPV6 58
#if 0
/*
 * IPv6 address
 */
struct in6_addr {
        union {
                uint8_t   __u6_addr8[16];
                uint16_t  __u6_addr16[8];
                uint32_t  __u6_addr32[4];
        } __u6_addr;                    /* 128-bit IP6 address */
#define s6_addr   __u6_addr.__u6_addr8
#define s6_addr8  __u6_addr.__u6_addr8
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32
};

typedef ulong ipaddrtype;

/*
 * Definition for internet protocol version 6.
 * RFC 2460
 */

struct ip6_hdr {
        union {
                struct ip6_hdrctl {
                        uint32_t ip6_un1_flow;  /* 20 bits of flow-ID */
                        uint16_t ip6_un1_plen;  /* payload length */
                        uint8_t  ip6_un1_nxt;   /* next header */
                        uint8_t  ip6_un1_hlim;  /* hop limit */
                } ip6_un1;
                uint8_t ip6_un2_vfc;    /* 4 bits version, top 4 bits class */
        } ip6_ctlun;
        struct in6_addr ip6_src;        /* source address */
        struct in6_addr ip6_dst;        /* destination address */
} __attribute__((__packed__));

/*
 * ICMPv6 header (RFC2463)
 */
typedef struct icmp6_hdr {
    uint8_t icmp6_type;         /* type field */
    uint8_t icmp6_code;         /* code field */
    uint16_t icmp6_cksum;       /* checksum field */
    union
    {
        uint32_t icmp6_un_data32[1];    /* type-specific field */
        uint16_t icmp6_un_data16[2];    /* type-specific field */
        uint8_t icmp6_un_data8[4];      /* type-specific field */
    }
    icmp6_dataun;
} icmp6_hdr_t;

typedef struct addrtype_ {
    char type;
    char length;
    ipaddrtype ip_addr;
    in6_addr_t ipv6_addr;
} addrtype;


typedef struct ip6_hdr ip6_hdr_t;

typedef struct in6_addr in6_addr_t;

typedef struct in6_addr rpl_in6_address_t;
typedef rpl_in6_address_t dag_id_t;
#endif

typedef struct in6_addr an_v6addr_t;
typedef uint32_t an_v4addr_t;

typedef struct addrtype_ {
    char type;
    char length;
    an_v4addr_t ip_addr;
    an_v6addr_t ipv6_addr;
} addrtype;

typedef an_pak_linux_t paktype;
typedef ulong an_if_t;
typedef an_pak_linux_t an_pak_t;
//typedef struct ip6_hdr an_ip6_hdr;

typedef an_dummy_t dag_id_t;
typedef addrtype an_addr_t;

typedef struct icmp6_hdr an_icmp6_hdr_t;
typedef struct ip6_hdr an_ipv6_hdr_t;

//typedef ether_hdr an_ether_hdr_t;
typedef an_dummy_t an_ether_hdr_t;

//typedef tableid_t an_iptable_t;
typedef an_dummy_t an_iptable_t;

typedef int an_file_descr_t;

typedef enum an_file_open_flags_e_ {
    AN_FOF_READ_ONLY        = O_RDONLY,
    AN_FOF_WRITE_ONLY       = O_WRONLY,
    AN_FOF_READ_WRITE       = O_RDWR,
    AN_FOF_APPEND           = O_APPEND,
    AN_FOF_CREATE           = O_CREAT,
    AN_FOF_TRUNCATE         = O_TRUNC
} an_file_open_flags_e;

typedef enum an_file_seek_ref_e_ {
    AN_FILE_SEEK_SET     = 0,
    AN_FILE_SEEK_CUR     = 1,
    AN_FILE_SEEK_END     = 2,
} an_file_seek_ref_e;

//typedef ipv6_SEND_secmode_type an_ipv6_SEND_secmode_type;

typedef enum an_afi_t_ {
    AN_AF_IPv4 = 0,
    AN_AF_IPv6,
} an_afi_t;


//typedef PKI_EnrollMessage an_enroll_msg_t;
typedef uint32_t an_enroll_msg_t;

/*
 * Defines the type of DAG that is being built...it could be storing
 * or non-storing...it is set in the MOP (Mode of Operation) in the
 * DAG instance ID
 */
typedef enum rpl_inst_type_ {
    RPL_INSTANCE_STORING = 1,
    RPL_INSTANCE_NONSTORING
} rpl_inst_type_t;


typedef enum rpl_ocp_type_ {
    RPL_OCP_NONE,
    RPL_OCP_ETX,
    RPL_OCP_LATENCY
} rpl_ocp_type_t;


/*
 * Return values from xos parser sal functions
 */
typedef enum rpl_cfg_sal_rc_ {
    RPL_CFG_SAL_OK,
    RPL_CFG_SAL_IS_ACTIVE,
    RPL_CFG_SAL_NOT_ACTIVE,
    RPL_CFG_SAL_BAD_PARM,
    RPL_CFG_SAL_IN_CONFLICT,
    RPL_CFG_SAL_ALLOC_FAIL,
    RPL_CFG_SAL_FAIL,
    RPL_CFG_SAL_NO_CHANGE,
    RPL_CFG_SAL_NOT_FOUND,
    RPL_CFG_SAL_INCOMPLETE,
    RPL_CFG_SAL_VRF_FAILURE,
    RPL_CFG_SAL_IPV6_INSTALL_FAILURE,
    RPL_CFG_SAL_ALREADY_EXISTS
} rpl_cfg_sal_rc_t;

typedef enum rpl_info_flags_ {
  NO_SUB_INTERFACE = 1 << 0,
  NO_VRF_PREFIX    = 1 << 1,
  REDISTRIBUTE_CONNECTED_BY_DEFAULT  = 1 << 2,
  NO_GLOBAL_ROUTE_ADDITION = 1 << 3,
  NO_NVGEN = 1 << 4,
  WALK_VRF_ONLY = 1 << 5,
  NO_DATA_PATH_VALIDATION = 1 << 6,
  NO_CONNECTED_ROUTE_DELETION = 1 << 7,
  NO_TRICKLE_TIMER = 1 << 8
} rpl_info_flags_t;

typedef struct rpl_info_ {
  an_dummy_t dag_addr;
  uint16_t   ocp;
  rpl_inst_type_t inst_type;
  rpl_ocp_type_t ocp_type;
  an_dummy_t if_h;
  uint8_t    vrf_name[32];
  uint32_t vrf_id;
  uint32_t vrf_table_id;
  uint8_t    inst_id;
  boolean  i_am_root;
  rpl_info_flags_t rpl_info_flags;
} rpl_info_t;

typedef struct an_linux_chunk_t_ {
    uint16_t chunk_size;
    uint16_t chunkpool_size;
    uint8_t *chunkpool_id;
    uint16_t refcount;
} an_linux_chunk_t;


typedef an_dummy_t rpl_if_h;
typedef rpl_info_t an_rpl_info_t;
//typedef uint32_t an_rpl_info_t;
typedef rpl_info_flags_t an_rpl_info_flags_t;
//typedef uint32_t an_rpl_info_flags_t;

typedef struct nd_neighbor_advert an_nd_nbr_advert;

//typedef ipv6_nd_opt_hdr an_ipv6_nd_opt_hdr; 

typedef an_linux_timer_t an_timer;
//typedef an_dummy_t chunk_type;
typedef an_linux_timer_t an_mgd_timer;
typedef an_dummy_t an_crypto_ss_cnct_id;
typedef an_linux_chunk_t an_mem_chunk_t;
typedef an_linux_chunk_t an_mem_chunkpool_t;
typedef ulong aaa_mlist_handle;
typedef uint32_t aaa_server_handle;
typedef uint32_t aaa_sg_handle;
//typedef dot1q_qinq_vlan_id_t an_dot1q_qinq_vlan_id_t;
typedef an_dummy_t an_dot1q_qinq_vlan_id_t;
typedef uint32_t an_idbtype;
typedef uint32_t an_hwidbtype;
typedef uint32_t an_crypto_ss_event_msg;
//typedef unsigned int size_t;
typedef enum an_pak_subblock_index_t_ {
    PAK_SUBBLOCK_MAX = 0
}an_pak_subblock_index_t;

typedef enum {
    IPV6_ND_FEAT_RC_OK,
    IPV6_ND_FEAT_RC_DROP,
    IPV6_ND_FEAT_RC_CONSUMED,
} an_ipv6_nd_feat_rc_t;


#define AN_ID_MGR_INVALID_HANDLE 0

#define AN_AAA_SERVER_HANDLE_INVALID AN_ID_MGR_INVALID_HANDLE
#define AN_AAA_SG_HANDLE_INVALID AN_ID_MGR_INVALID_HANDLE

#define AN_AAA_SECRET_KEY_LENGTH  255

extern an_if_t an_source_if;
/*
 * Temp PATCH : TODO
 */
extern boolean platform_ready;
#endif
