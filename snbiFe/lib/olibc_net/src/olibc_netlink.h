#ifndef __OLIBC_NETLINK_H__
#define __OLIBC_NETLINK_H__

#include <sys/uio.h>
#include <linux/netlink.h>
#include <olibc_common.h>

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
olibc_nl_send_req(olibc_nl_sock_t *nl_sock, struct iovec *io, uint32_t io_cnt);

extern boolean 
olibc_nl_msg_recv(olibc_nl_sock_t *nl_sock, char *nlmsg_buf, 
                  uint32_t max_buf_len, uint32_t *nlmsg_len);

#endif
