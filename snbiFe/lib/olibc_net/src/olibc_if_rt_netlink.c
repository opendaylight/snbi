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

    if (!olibc_if_rt_nl_send_req(&if_iter_hdl->nl_sock, 
                                 RTM_GETLINK, AF_PACKET, NLM_F_REQUEST |
                                 NLM_F_DUMP)) {
        return OLIBC_RETVAL_FAILED;
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
                            olibc_if_info_t *if_info)
{
    struct nlmsghdr *curr_data_ptr;

    if (!if_iter_hdl || !if_info) {
        return OLIBC_RETVAL_FAILED;
    }

    if (if_iter_hdl->iter_done) {
        return OLIBC_RETVAL_NO_MORE_DATA;
    }

    if (if_iter_hdl->data_parsed == if_iter_hdl->nlmsg_len) {
        if (!olibc_if_rt_nl_recv_resp(&if_iter_hdl->nl_sock,
                    if_iter_hdl->nlmsg_buf,
                    MAX_NL_MSG_LEN, 
                    &if_iter_hdl->nlmsg_len)) {
            return OLIBC_RETVAL_FAILED;
        }
        if_iter_hdl->data_parsed = 0;
        if_iter_hdl->curr_buff_ptr = if_iter_hdl->nlmsg_buf;
    }

    curr_data_ptr = (struct nlmsghdr *)if_iter_hdl->curr_buff_ptr;

    if (NLMSG_OK(curr_data_ptr, if_iter_hdl->nlmsg_len)) {
        switch (curr_data_ptr->nlmsg_type) {
            case NLMSG_DONE:
                if_iter_hdl->iter_done = TRUE;
                break;
            case RTM_NEWLINK:
                memset(if_info, 0, sizeof(olibc_if_info_t));
                if (!olibc_if_rt_netlink_parse_info(curr_data_ptr, if_info)) {
                    return OLIBC_RETVAL_FAILED;
                }
                break;
            default:
                printf("\n msg type received %d not requested",
                        data_ptr->nlmsg_type);
                break;
        }
        curr_data_ptr = NLMSG_NEXT(curr_data_ptr, if_iter_hdl->nlmsg_len);
    }
    if_iter_hdl->data_parsed = curr_data_ptr - if_iter_hdl->curr_buff_ptr
    return OLIBC_RETVAL_SUCCESS;
}

boolean
olibc_if_rt_netlink_parse_info (struct nlmsghdr *nlh, olibc_if_info_t *if_info)
{
    int len;
    struct ifinfomsg *iface;
    struct rtattr *attribute;
    struct rtnl_link_stats *stats;

    /* loop over all attributes for the NEWLINK message */
    for (attribute = IFLA_RTA(iface);
         RTA_OK(attribute, len);
         attribute = RTA_NEXT(attribute, len)) {

        switch(attribute->rta_type) {
            case IFLA_IFNAME:
                strncpy(if_info->if_name, (char *) RTA_DATA(attribute), MAX_IF_NAME_LEN);
                if_info->if_index = iface->ifi_index;
                if_info->if_state = iface->ifi_flags & IFF_UP ? IFF_UP:IF_DOWN;
                if_info->is_loopback = iface->ifi_flags & IFF_LOOPBACK;
                break;
            default:
                printf("\nInvalid attribute type found");
                return FALSE;
        }
    }
    return TRUE;
}


static inline boolean
olibc_if_rt_nl_recv_resp (olibc_nl_sock_t *nl_sock, char *nlmsg_buf, 
                          uint32_t max_buf_len, uint32_t *nlmsg_len)
{
    return olibc_nl_msg_recv(nl_sock, nlmsg_buf, max_buf_len, nlmsg_len);
}

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

    if (olibc_nl_send_req(nl_sock, &io, 1)) {
        return FALSE;
    }

    return TRUE;
}
                               
