#ifndef __OLIBC_NETLINK_H__
#define __OLIBC_NETLINK_H__

#include <linux/netlink.h>

typedef struct olibc_nl_sock_t_ {
    int pid;
    int seq_no;
    int nl_fd;
} olibc_nl_sock_t;



extern boolean 
olibc_nl_sock_init(olibc_nl_sock_t *nl_sock, uint32_t nl_pf);

extern boolean
olibc_nl_sock_bind(olibc_nl_sock_t *nl_sock, uint32_t mgroups);

extern boolean
olibc_nl_sock_uninit(olibc_nl_sock_t *nl_sock);

extern boolean
olibc_nl_send_request(olibc_nl_sock_t *nl_sock, uint32_t nlmsg_type, uint32_t
        req_family, uint32_t flags);

#endif
