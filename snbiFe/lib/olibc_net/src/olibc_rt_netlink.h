#ifndef __OLIBC_RT_NETLINK_H__
#define __OLIBC_RT_NETLINK_H__

#include "olibc_netlink.h"
#include <linux/rtnetlink.h>

typedef struct olibc_rt_nl_gen_req_t_ {
    struct nlmsghdr nl_hdr;
    struct rtgenmsg gen_msg;
} olibc_rt_nl_gen_req_t;

extern boolean
olibc_rt_nl_send_req(olibc_nl_sock_t *nl_sock,
                     uint32_t nlmsg_type,
                     uint32_t req_family,
                     uint32_t flags);
#endif
