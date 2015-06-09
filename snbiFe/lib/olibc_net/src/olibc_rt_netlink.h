#ifndef __OLIBC_RT_NETLINK_H__
#define __OLIBC_RT_NETLINK_H__

#include "olibc_netlink.h"

typedef struct olibc_rt_nl_gen_req_t_ {
    struct nlmsghdr nl_hdr;
    struct rtgenmsg gen_msg;
} olibc_rt_nl_gen_req_t;

#endif
