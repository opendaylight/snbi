#ifndef __OLIBC_ADDR_RT_NETLINK_H__
#define __OLIBC_ADDR_RT_NETLINK_H__

#include <olibc_common.h>
#include <olibc_addr.h>
#include "olibc_netlink.h"
#include "olibc_rt_netlink.h"

#define OLIBC_ADDR_OPER_FLAG_IPV4_REQ_SENT 0x01
#define OLIBC_ADDR_OPER_FLAG_IPV6_REQ_SENT 0x02
#define OLIBC_ADDR_OPER_FLAG_IPV4_ITER_DONE 0x04
#define OLIBC_ADDR_OPER_FLAG_IPV6_ITER_DONE 0x08
#define OLIBC_ADDR_OPER_FLAG_IPV4_ITERATION 0x10
#define OLIBC_ADDR_OPER_FLAG_IPV6_ITERATION 0x20


typedef struct olibc_addr_iterator_t_ {
    olibc_nl_sock_t nl_sock;
    char nlmsg_buf[OLIBC_MAX_NL_MSG_LEN];
    uint32_t nlmsg_len;
    uint32_t pending_data_len;
    char *curr_buff_ptr;
    uint8_t oper_flags;
} olibc_addr_rt_nl_iterator_t;

#endif
