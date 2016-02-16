#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "olibc_netlink.h"
#include <olibc_common.h>
#include <olibc_log.h>

boolean
olibc_nl_sock_init (olibc_nl_sock_t *nl_sock, uint32_t nl_pf)
{
    int fd;
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
        olibc_log_error("\nFailed to bind socket, NULL nl sock");
        return FALSE;
    }
    
    memset(&local_nl_addr, 0, sizeof(local_nl_addr));

    local_nl_addr.nl_family = AF_NETLINK;
    local_nl_addr.nl_pid = nl_sock->pid;
    local_nl_addr.nl_groups = mgroups;

    if (bind(nl_sock->nl_fd, (struct sockaddr *)&local_nl_addr,
            sizeof(local_nl_addr)) < 0) {
        olibc_log_error("\nFailed to bind socket");
        close(nl_sock->nl_fd);
        return FALSE;
    }

    olibc_log_debug("\nNL Sock bind successful");
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
olibc_nl_send_req (olibc_nl_sock_t *nl_sock, 
                   struct iovec *io, uint32_t iov_cnt)
{
    struct msghdr msg = {0};
    struct  sockaddr_nl kernel_nl_addr = {0};

    kernel_nl_addr.nl_family = AF_NETLINK;
    msg.msg_iov = io;
    msg.msg_iovlen = iov_cnt;

    msg.msg_name = &kernel_nl_addr;
    msg.msg_namelen = sizeof(kernel_nl_addr);

    if (sendmsg(nl_sock->nl_fd, (struct msghdr *) &msg, 0) < 0) {
        return FALSE;
    }

    return TRUE;
}

boolean
olibc_nl_msg_recv (olibc_nl_sock_t *nl_sock, char *nlmsg_buf, uint32_t
        max_buf_len, uint32_t *nlmsg_len)
{
    struct nlmsghdr *nl_msg_resp_hdr;
    struct msghdr msg;
    struct iovec io_reply;
    struct sockaddr_nl kernel_nl_addr = {0};

    kernel_nl_addr.nl_family = AF_NETLINK;

    if (!nlmsg_buf) {
        return FALSE;
    }

    memset(&io_reply, 0, sizeof(io_reply));
    memset(&msg, 0, sizeof(msg));

    io_reply.iov_base = nlmsg_buf;
    io_reply.iov_len = max_buf_len;

    msg.msg_iov = &io_reply;
    msg.msg_iovlen = 1;
    msg.msg_name = &kernel_nl_addr;
    msg.msg_namelen = sizeof(kernel_nl_addr);
    *nlmsg_len = recvmsg(nl_sock->nl_fd, &msg, 0);

    nl_msg_resp_hdr = (struct nlmsghdr *)nlmsg_buf;

    if (!NLMSG_OK(nl_msg_resp_hdr, *nlmsg_len)) {
        return FALSE;
    }

    return TRUE;
}
