#include "olibc_if_rt_nl.h"


olibc_retval_t
olibc_if_iterator_create (olibc_if_iterator_hdl *if_iter_hdl,
                          olibc_if_iterator_filter_t *if_iter_filter)
{
    olibc_if_rt_nl_iterator_t *if_rt_nl_iter;

    if (!if_iter_hdl || !if_iter_filter) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    OLIBC_MALLOC_CHECK(if_rt_nl_iter, sizeof(olibc_if_rt_nl_iterator_t),
                       __THIS_FUNCTION__, retval);

    if_rt_nl_iter->filter_flags = if_iter_filter->flags;

    if (!olibc_nl_sock_init(&if_rt_nl_iter->nl_sock, 
                            NETLINK_ROUTE)) {
        olibc_free((void **)&if_rt_nl_iter);
        return OLIBC_RETVAL_FAILED;
    }

    if (!olibc_nl_sock_bind(&if_rt_nl_iter->nl_sock, 0)) {
        olibc_free((void **)&if_rt_nl_iter);
    }

    *if_iter_hdl = if_rt_nl_iter;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_if_iterator_destroy (olibc_if_iterator_hdl *if_iter_hdl)
{
    olibc_if_rt_nl_iterator_t *rt_nl_iter = NULL;
    if (!if_iter_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    rt_nl_iter = *if_iter_hdl;

    olibc_nl_sock_uninit(&rt_nl_iter->nl_sock);

    olibc_free((void **)&rt_nl_iter);

    *if_iter_hdl = NULL;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_if_iterator_get_next (olibc_if_iterator_hdl if_iter_hdl,
                            olibc_if_info_t *if_info_t)
{
    if (!if_iter_hdl || !if_info_t) {
        return OLIBC_RETVAL_FAILED;
    }

    if (!olibc_if_rt_nl_send_req(&if_iter_hdl->nl_sock, 
                                 RTM_GETLINK, AF_PACKET, NLM_F_REQUEST |
                                 NLM_F_DUMP)) {
        return OLIBC_RETVAL_FAILED;
    }

    if (!olibc_if_rt_nl_recv_resp(&if_iter_hdl->nl_sock)) {
        return OLIBC_RETVAL_FAILED;
    }

    return OLIBC_RETVAL_SUCCESS;
}

boolean
olibc_if_rt_nl_recv_resp (olibc_nl_sock_t *nl_sock

boolean
olibc_if_rt_nl_send_req (olibc_nl_sock_t *nl_sock, 
                         uint32_t nlmsg_type,
                         uint32_t req_family, 
                         uint32_t flags)
{
    olibc_rt_nl_gen_req_t nl_req = {0};
    struct iovec io = {0};

    if (!nl_sock) {
        return FALSE;
    }

    nl_req.nl_hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    nl_req.nl_hdr.nlmsg_type = nlmsg_type;
    nl_req.nl_hdr.nlmsg_flags = flags;
    nl_req.gen_msg.rtgen_family = req_family;

    io.iov_base = &nl_req;
    io.iov_len = nl_req.nl_hdr.nlmsg_len;

    if (olibc_nl_send_request(nl_sock, &io, 1)) {
        return FALSE;
    }

    return TRUE;
}
                               
