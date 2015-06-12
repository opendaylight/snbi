#include <string.h>
#include <net/if.h>
#include <sys/uio.h>
#include <olibc_log.h>
#include <sys/socket.h>
#include <olibc_common.h>
#include "olibc_rt_netlink.h"
#include "olibc_if_rt_netlink.h"

boolean
olibc_if_rt_nl_send_req (olibc_nl_sock_t *nl_sock, 
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

static inline boolean
olibc_if_rt_nl_recv_resp (olibc_nl_sock_t *nl_sock, char *nlmsg_buf, 
                          uint32_t max_buf_len, uint32_t *nlmsg_len)
{
    return olibc_nl_msg_recv(nl_sock, nlmsg_buf, max_buf_len, nlmsg_len);
}

boolean
olibc_if_rt_netlink_parse_info (struct nlmsghdr *nlh, 
                                olibc_if_info_t *if_info)
{
    int len;
    uint32_t hw_addr_len;
    struct ifinfomsg *iface;
    struct rtattr *attribute;

    if (nlh->nlmsg_type != RTM_NEWLINK) {
        return FALSE;
    }

    iface = NLMSG_DATA(nlh);
    len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

    if_info->if_index = iface->ifi_index;
    if_info->if_state = iface->ifi_flags & IFF_UP ? IF_UP:IF_DOWN;
    if_info->is_loopback = iface->ifi_flags & IFF_LOOPBACK;
    if_info->hw_type = iface->ifi_type;

    /* loop over all attributes for the NEWLINK message */
    for (attribute = IFLA_RTA(iface);
         RTA_OK(attribute, len);
         attribute = RTA_NEXT(attribute, len)) {

        switch (attribute->rta_type) {
            case IFLA_IFNAME:
                strncpy(if_info->if_name, 
                        (char *) RTA_DATA(attribute), 
                        MAX_IF_NAME_LEN);
                break;
            case IFLA_ADDRESS:
                hw_addr_len = RTA_PAYLOAD(attribute);
                hw_addr_len = hw_addr_len > MAX_IF_HW_ADDR ? 
                                    MAX_IF_HW_ADDR : hw_addr_len;
                if_info->hw_addr_len = hw_addr_len;
                memcpy(if_info->hw_addr, RTA_DATA(attribute), hw_addr_len);
                break;
            case IFLA_LINK:
                olibc_log_debug("\nattribute type IFLA LINK");
                break;
            case IFLA_STATS:
                olibc_log_debug("\nattribute type IFLA STATs");
                break;
            case IFLA_QDISC:
                olibc_log_debug("\nattribute type IFLA QDisc");
                break;
            case IFLA_BROADCAST:
                olibc_log_debug("\nattribute type IFLA broadcast");
                break;
            case IFLA_MTU:
                olibc_log_debug("\nattribute type IFLA MTU");
                break;
            default:
                olibc_log_debug("\nUnhandled attribute type");
        }
    }
    return TRUE;
}

olibc_retval_t
olibc_if_iterator_create (olibc_if_iterator_filter_t *if_iter_filter,
                          olibc_if_iterator_hdl *if_iter_hdl)

{
    olibc_retval_t retval;
    olibc_if_rt_nl_iterator_t *if_rt_nl_iter = NULL;

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
        return OLIBC_RETVAL_FAILED;
    }

    if (!olibc_if_rt_nl_send_req(&if_rt_nl_iter->nl_sock, 
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
    uint32_t len;

    if (!if_iter_hdl || !if_info) {
        return OLIBC_RETVAL_FAILED;
    }

    if (if_iter_hdl->iter_done) {
        return OLIBC_RETVAL_NO_MORE_DATA;
    }

    if (!if_iter_hdl->pending_data_len) {
        if (!olibc_if_rt_nl_recv_resp(&if_iter_hdl->nl_sock,
                    if_iter_hdl->nlmsg_buf,
                    MAX_NL_MSG_LEN, 
                    &if_iter_hdl->nlmsg_len)) {
            return OLIBC_RETVAL_FAILED;
        }
        if_iter_hdl->pending_data_len = if_iter_hdl->nlmsg_len;
        if_iter_hdl->curr_buff_ptr = if_iter_hdl->nlmsg_buf;
    }

    curr_data_ptr = (struct nlmsghdr *)if_iter_hdl->curr_buff_ptr;
    len = if_iter_hdl->pending_data_len;

    if (NLMSG_OK(curr_data_ptr, len)) {
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
                        curr_data_ptr->nlmsg_type);
                break;
        }
        curr_data_ptr = NLMSG_NEXT(curr_data_ptr, len);
    } else {
        printf("\nFailed to get next nlmsg hdr");
        if_iter_hdl->iter_done = TRUE;
        return OLIBC_RETVAL_FAILED;
    }

    if_iter_hdl->pending_data_len = len;
    if_iter_hdl->curr_buff_ptr = (char *)curr_data_ptr;

    if (if_iter_hdl->iter_done) {
        return OLIBC_RETVAL_NO_MORE_DATA;
    }

    return OLIBC_RETVAL_SUCCESS;
}

