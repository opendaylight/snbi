#include "olibc_rt_netlink.h"
#include <string.h>

boolean
olibc_rt_nl_send_req (olibc_nl_sock_t *nl_sock,
                      uint32_t nlmsg_type,
                      uint32_t req_family,
                      uint32_t flags)
{
    olibc_rt_nl_gen_req_t nl_req;
    struct iovec io;

    if (!nl_sock) {
        return FALSE;
    }

    memset(&nl_req, 0, sizeof(olibc_rt_nl_gen_req_t));
    memset(&io, 0, sizeof(struct iovec));

    nl_req.nl_hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    nl_req.nl_hdr.nlmsg_type = nlmsg_type;
    nl_req.nl_hdr.nlmsg_flags = flags;
    nl_req.gen_msg.rtgen_family = req_family;

    io.iov_base = &nl_req;
    io.iov_len = nl_req.nl_hdr.nlmsg_len;

    if (!olibc_nl_send_req(nl_sock, &io, 1)) {
        return FALSE;
    }

    return TRUE;
}
