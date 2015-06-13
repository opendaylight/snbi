#ifndef __OLIBC_IF_RT_NETLINK_H__
#define __OLIBC_IF_RT_NETLINK_H__

#include <olibc_if.h>
#include "olibc_netlink.h"

typedef struct olibc_if_iterator_t_ {
    olibc_nl_sock_t nl_sock;
    uint32_t filter_flags;
    char nlmsg_buf[MAX_NL_MSG_LEN];
    uint32_t nlmsg_len;
    uint32_t pending_data_len;
    char *curr_buff_ptr;
    boolean iter_done;
} olibc_if_rt_nl_iterator_t;

#endif
