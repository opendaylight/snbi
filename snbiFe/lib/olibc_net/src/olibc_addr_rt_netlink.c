#include "olibc_addr_rt_netlink.h"
#include <arpa/inet.h>
#include <olibc_log.h>
#include <string.h>

boolean
olibc_addr_rt_netlink_parse_info (struct nlmsghdr *nlh,
                                 olibc_addr_info_t *addr_info,
                                 uint32_t *if_index)
{
    int len;
    struct rtattr *attribute;
    struct ifaddrmsg *addr_msg;
    struct in6_addr *addrv6;
    struct in_addr *addrv4;
    char dbg_str[INET6_ADDRSTRLEN];

    if ((nlh->nlmsg_type != RTM_NEWADDR) &&
        (nlh->nlmsg_type != RTM_DELADDR)) {
        return FALSE;
    }

    addr_msg = NLMSG_DATA(nlh);
    len = IFA_PAYLOAD(nlh);

    *if_index = addr_msg->ifa_index;
    addr_info->addr_family = addr_msg->ifa_family;
    addr_info->prefixlen = addr_msg->ifa_prefixlen;

    switch (addr_msg->ifa_scope) {
        case RT_SCOPE_UNIVERSE:
            addr_info->scope = OLIBC_ADDR_SCOPE_UNIVERSE;
            break;
        case RT_SCOPE_SITE:
            addr_info->scope = OLIBC_ADDR_SCOPE_SITE;
            break;
        case RT_SCOPE_LINK:
            addr_info->scope = OLIBC_ADDR_SCOPE_LINK;
            break;
        case RT_SCOPE_HOST:
            addr_info->scope = OLIBC_ADDR_SCOPE_HOST;
            break;
        case RT_SCOPE_NOWHERE:
            addr_info->scope = OLIBC_ADDR_SCOPE_NOWHERE;
            break;
    }

    for (attribute = IFA_RTA(addr_msg);
         RTA_OK(attribute, len);
         attribute = RTA_NEXT(attribute, len)) {

        switch (attribute->rta_type) {
            case IFA_ADDRESS:
                olibc_log_debug("\nIFA address %s", 
                        inet_ntop(addr_msg->ifa_family,
                        RTA_DATA(attribute), dbg_str,
                        sizeof(dbg_str)));
            case IFA_LOCAL:
                olibc_log_debug("\nIFA local %s", 
                        inet_ntop(addr_msg->ifa_family,
                        RTA_DATA(attribute), dbg_str,
                        sizeof(dbg_str)));
                if (addr_info->addr_family == AF_INET) { 
                    addrv4 = (struct in_addr *)RTA_DATA(attribute);
                    addr_info->addrv4 = *addrv4;
                } 

                if (addr_info->addr_family == AF_INET6) {
                    addrv6 = (struct in6_addr *)RTA_DATA(attribute);
                    addr_info->addrv6 = *addrv6;
                }
                break;
            case IFA_BROADCAST:
                olibc_log_debug("\nIFA broadcast %s", 
                        inet_ntop(addr_msg->ifa_family,
                        RTA_DATA(attribute), dbg_str, 
                        sizeof(dbg_str)));
                break;
            case IFA_ANYCAST:
                olibc_log_debug("\nIFA Anycast %s", 
                        inet_ntop(addr_msg->ifa_family, 
                        RTA_DATA(attribute), 
                        dbg_str, sizeof(dbg_str)));
                break;
            case IFA_MULTICAST:
                olibc_log_debug("\nIFA multicast %s", 
                        inet_ntop(addr_msg->ifa_family, 
                        RTA_DATA(attribute), dbg_str,
                        sizeof(dbg_str)));
                break;
            case IFA_LABEL:
                olibc_log_debug("\nIFA label %s", (char *) RTA_DATA(attribute));
                break;
            case IFA_CACHEINFO:
                olibc_log_debug("\nIFA cache info");
            default:
                olibc_log_error("\nUnhandled addr attr type %d", 
                        attribute->rta_type);
                break;
        }
    }
    return TRUE;
}

olibc_retval_t
olibc_addr_iterator_create (olibc_addr_iterator_filter_t *filter_info,
                            olibc_addr_iterator_hdl *iter_hdl)
{
    olibc_retval_t retval;
    olibc_addr_rt_nl_iterator_t *add_rt_nl_iter = NULL;

    if (!iter_hdl || !filter_info || !filter_info->flags) {
        olibc_log_error("Invalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    OLIBC_MALLOC_CHECK(add_rt_nl_iter, sizeof(olibc_addr_rt_nl_iterator_t),
            __THIS_FUNCTION__, retval);

    if (!(filter_info->flags & OLIBC_FLAG_IPV4)) {
        add_rt_nl_iter->oper_flags |= OLIBC_ADDR_OPER_FLAG_IPV4_ITER_DONE;
    }

    if (!(filter_info->flags & OLIBC_FLAG_IPV6)) {
        add_rt_nl_iter->oper_flags |= OLIBC_ADDR_OPER_FLAG_IPV6_ITER_DONE;
    }

    if (!olibc_nl_sock_init(&add_rt_nl_iter->nl_sock,
                            NETLINK_ROUTE)) {
        olibc_free((void **)&add_rt_nl_iter);
        olibc_log_error("Failed to init socket");
        return OLIBC_RETVAL_FAILED;
    }

    if (!olibc_nl_sock_bind(&add_rt_nl_iter->nl_sock, 0)) {
        olibc_nl_sock_uninit(&add_rt_nl_iter->nl_sock);
        olibc_free((void **)&add_rt_nl_iter);
        return OLIBC_RETVAL_FAILED;
    }

    *iter_hdl = add_rt_nl_iter;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_addr_recv (olibc_addr_iterator_hdl iter_hdl,
                 olibc_addr_info_t *addr_info,
                 uint32_t *if_index,
                 olibc_addr_event_type_t *addr_event)
{
    uint32_t len;
    struct nlmsghdr *curr_data_ptr;

    if (!(iter_hdl->pending_data_len)) {
        memset(iter_hdl->nlmsg_buf, 0, OLIBC_MAX_NL_MSG_LEN);
        if (!olibc_nl_msg_recv(&iter_hdl->nl_sock,
                    iter_hdl->nlmsg_buf,
                    OLIBC_MAX_NL_MSG_LEN,
                    &iter_hdl->nlmsg_len)) {
            return OLIBC_RETVAL_FAILED;
        }
        iter_hdl->pending_data_len = iter_hdl->nlmsg_len;
        iter_hdl->curr_buff_ptr = iter_hdl->nlmsg_buf;
    }
    
    curr_data_ptr = (struct nlmsghdr *)iter_hdl->curr_buff_ptr;
    len = iter_hdl->pending_data_len; 
    
    if (NLMSG_OK(curr_data_ptr, len)) {
        switch (curr_data_ptr->nlmsg_type) {
            case NLMSG_DONE:
                if (iter_hdl->oper_flags & 
                    OLIBC_ADDR_OPER_FLAG_IPV4_ITERATION) {
                    iter_hdl->oper_flags &=
                            ~OLIBC_ADDR_OPER_FLAG_IPV4_ITERATION;
                    iter_hdl->oper_flags |= OLIBC_ADDR_OPER_FLAG_IPV4_ITER_DONE;
                } 
                if (iter_hdl->oper_flags & 
                    OLIBC_ADDR_OPER_FLAG_IPV6_ITERATION) {
                    iter_hdl->oper_flags &=
                        ~OLIBC_ADDR_OPER_FLAG_IPV6_ITERATION;
                    iter_hdl->oper_flags |= OLIBC_ADDR_OPER_FLAG_IPV6_ITER_DONE;
                }
                break;
            case RTM_NEWADDR:
                *addr_event = ADDR_EVENT_NEW;
                memset(addr_info, 0, sizeof(olibc_addr_info_t));
                if (!olibc_addr_rt_netlink_parse_info(curr_data_ptr,
                            addr_info, if_index)) {
                    return OLIBC_RETVAL_FAILED;
                }
                break;
            case RTM_DELADDR:
                *addr_event = ADDR_EVENT_DEL;
                memset(addr_info, 0, sizeof(olibc_addr_info_t));
                if (!olibc_addr_rt_netlink_parse_info(curr_data_ptr,
                            addr_info, if_index)) {
                    return OLIBC_RETVAL_FAILED;
                }
                break;
            default:
                olibc_log_error("\n msg type %d received not requested",
                        curr_data_ptr->nlmsg_type);
                break;
        }
        curr_data_ptr = NLMSG_NEXT(curr_data_ptr, len);
    } else { 
        olibc_log_error("\nFailed to get next nlmsg hdr");
        iter_hdl->oper_flags |= (OLIBC_ADDR_OPER_FLAG_IPV4_ITER_DONE |
                OLIBC_ADDR_OPER_FLAG_IPV6_ITER_DONE);
        return OLIBC_RETVAL_FAILED;
    }

    iter_hdl->pending_data_len = len;
    iter_hdl->curr_buff_ptr = (char *)curr_data_ptr;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_addr_iterator_destroy (olibc_addr_iterator_hdl *iter_hdl)
{
    olibc_addr_rt_nl_iterator_t *iter;

    if (!iter_hdl) {
        olibc_log_error("Invalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    iter = *iter_hdl;

    olibc_nl_sock_uninit(&iter->nl_sock);
    olibc_free((void **)iter_hdl);
    *iter_hdl = NULL;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_addr_iterator_get_next (olibc_addr_iterator_hdl iter_hdl, 
                              olibc_addr_info_t *addr_info,
                              uint32_t *if_index,
                              olibc_addr_event_type_t *addr_event)
{
    olibc_retval_t retval;

    if (!iter_hdl || !addr_info || !if_index || !addr_event) {
        olibc_log_error("Invalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if ((iter_hdl->oper_flags & OLIBC_ADDR_OPER_FLAG_IPV4_ITER_DONE)  &&
        (iter_hdl->oper_flags & OLIBC_ADDR_OPER_FLAG_IPV6_ITER_DONE)) {
        return OLIBC_RETVAL_NO_MORE_DATA;
    }

    if (!(iter_hdl->oper_flags & OLIBC_ADDR_OPER_FLAG_IPV4_ITER_DONE)) {
        if (!(iter_hdl->oper_flags & OLIBC_ADDR_OPER_FLAG_IPV4_REQ_SENT)) {
            if (!olibc_rt_nl_send_req(&iter_hdl->nl_sock, 
                                      RTM_GETADDR, AF_INET,
                                      NLM_F_REQUEST|NLM_F_DUMP)) {
                return OLIBC_RETVAL_FAILED;
            }
            olibc_log_debug("IPV4 address request sent");
            iter_hdl->oper_flags |= OLIBC_ADDR_OPER_FLAG_IPV4_REQ_SENT;
            iter_hdl->oper_flags &= ~OLIBC_ADDR_OPER_FLAG_IPV6_ITERATION;
            iter_hdl->oper_flags |= OLIBC_ADDR_OPER_FLAG_IPV4_ITERATION;
        }
        retval = olibc_addr_recv(iter_hdl, addr_info, if_index, addr_event);

        if (retval != OLIBC_RETVAL_SUCCESS) {
            return retval;
        }

        if (iter_hdl->oper_flags & OLIBC_ADDR_OPER_FLAG_IPV4_ITERATION) {
            return OLIBC_RETVAL_SUCCESS;
        }
    } 
    
    if (!(iter_hdl->oper_flags &
          OLIBC_ADDR_OPER_FLAG_IPV6_ITER_DONE)) {
        if (!(iter_hdl->oper_flags & OLIBC_ADDR_OPER_FLAG_IPV6_REQ_SENT)) {
            if (!olibc_rt_nl_send_req(&iter_hdl->nl_sock,
                                      RTM_GETADDR, AF_INET6,
                                      NLM_F_REQUEST | NLM_F_DUMP)) {
                return OLIBC_RETVAL_FAILED;
            }
            olibc_log_debug("IPV6 address request sent");
            iter_hdl->oper_flags |= OLIBC_ADDR_OPER_FLAG_IPV6_REQ_SENT;
            iter_hdl->oper_flags &= ~OLIBC_ADDR_OPER_FLAG_IPV4_ITERATION;
            iter_hdl->oper_flags |= OLIBC_ADDR_OPER_FLAG_IPV6_ITERATION;
        }

        retval = olibc_addr_recv(iter_hdl, addr_info, if_index, addr_event);
        if (retval != OLIBC_RETVAL_SUCCESS) {
            return retval;
        }

        if (iter_hdl->oper_flags & OLIBC_ADDR_OPER_FLAG_IPV6_ITERATION) {
            return OLIBC_RETVAL_SUCCESS;
        }
    }
    

    if ((iter_hdl->oper_flags & OLIBC_ADDR_OPER_FLAG_IPV4_ITER_DONE)  &&
        (iter_hdl->oper_flags & OLIBC_ADDR_OPER_FLAG_IPV6_ITER_DONE)) {
        return OLIBC_RETVAL_NO_MORE_DATA;
    }

    return OLIBC_RETVAL_SUCCESS;
}
