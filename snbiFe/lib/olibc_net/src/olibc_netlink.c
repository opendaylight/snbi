#include "olibc_netlink.h"
#include <olibc_common.h>

boolean
olibc_nl_sock_init (olibc_nl_sock_t *nl_sock, uint32_t nl_pf)
{
    int sock_fd;
    int pid;
    struct sockaddr_nl local_nl_addr;

    if (!nl_sock) {
        return FALSE;
    }

    fd  = socket(AF_NETLINK, SOCK_RAW, nl_pf);

    memset(&local_nl_addr, 0, sizeof(local_nl_addr));
    pid = getpid();
    nl_sock->pid = pid;
    nl_sock->nl_fd = fd;
    nl_sock->seq_no = 0;

    return TRUE;
}



boolean
olibc_nl_sock_bind (olibc_nl_sock_t *nl_sock, uint32_t mgroups)
{
    struct sockaddr_nl local_nl_addr; 

    if (!nl_sock) {
        return FALSE;
    }
    
    memset(&local_nl_addr, 0, sizeof(local_nl_addr));

    local_nl_addr.nl_family = AF_NETLINK;
    local_nl_addr.nl_pid = pid;
    local_nl_addr.nl_groups = mgroups;

    if (bind(nl_sock->nl_fd, (struct sockaddr *)&local_nl_addr,
            sizeof(local_nl_addr)) < 0) {
        close(fd);
        return FALSE;
    }

    return TRUE;
}

boolean
olibc_nl_sock_uninit (olibc_nl_sock_t *nl_sock)
{
    if (!nl_sock) {
        return FALSE;
    }
    close(nl_sock->nl_fd);
    return TRUE;
}

boolean
olibc_nl_send_request(olibc_nl_sock_t *nl_sock, 
                      struct iovec *io, uint32_t iov_cnt)
{
    struct msghdr msg = {0};
    struct  sockaddr_nl kernel_nl_addr = {0};

    kernel_nl_addr.nl_family = AF_NETLINK;
    msg.msg_iov = io;
    msg.msg_iovlen = iov_cnt;

    msg.msg_name = &kernel_nl_addr;
    msg.msg_namelen = sizeof(kernel_nl_addr);

    if (sendmsg(rt_nt_sock->fd, (struct msghdr *) &msg, 0) < 0) {
        return FALSE;
    }

    return TRUE;
}
