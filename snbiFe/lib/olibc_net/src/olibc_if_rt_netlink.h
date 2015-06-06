#ifndef __OLIBC_IF_RT_NETLINK_H__
#define __OLIBC_IF_RT_NETLINK_H__

#include <olibc_if.h>

typedef struct olibc_if_iterator_t_ {
    olibc_nl_sock_t nl_sock;
    uint32_t filter_flags;
} olibc_if_rt_nl_iterator_t;

#endif
