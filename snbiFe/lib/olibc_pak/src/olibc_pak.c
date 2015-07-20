#include <olibc_log.h>
#include <arpa/inet.h>
#include <olibc_list.h>
#include <string.h>
#include "olibc_pak_internal.h"
//#include <netinet/in.h>
#include <linux/ipv6.h>
#include <sys/socket.h>

olibc_list_hdl pak_list_hdl = NULL;

#define OLIBC_MAX_ADDR_STR INET6_ADDRSTRLEN

#define AF_INET_STRING(_AF_) _AF_ == AF_INET ? "AF_INET":"AF_INET6"

olibc_retval_t
olibc_pak_create (olibc_pak_hdl *pak_hdl, olibc_pak_info_t *pak_info)
{
    olibc_retval_t retval;
    olibc_pak_t *pak = NULL;

    if (!pak_hdl || !pak_info) { 
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if (!pak_list_hdl) {
        retval = olibc_list_create(&pak_list_hdl, "Olibc Pak List");
        if (retval != OLIBC_RETVAL_SUCCESS || pak_list_hdl == NULL) {
            olibc_log_error("\nFailed to create pak list");
            return retval;
        }
        olibc_log_debug("\nPak list created");
    }

    retval = olibc_list_dequeue_node(pak_list_hdl, (void **)&pak); 

    if (pak) {
        pak->data_set_flags = 0;
        pak->data_length = 0;
        pak->in_ifindex = 0;
        pak->out_ifindex = 0;
        memset(&pak->src_sock_addr, 0, sizeof(struct sockaddr_storage));
        memset(&pak->dst_sock_addr, 0, sizeof(struct sockaddr_storage));
    } else {
        OLIBC_MALLOC_CHECK(pak, sizeof(olibc_pak_t), __THIS_FUNCTION__, retval);
        pak->max_pak_length = OLIBC_MAX_PAK_BUF_SIZE;
    }

    if (pak->max_pak_length < pak_info->max_pak_length) {
        olibc_list_insert_node(pak_list_hdl, NULL, pak_hdl);
        return OLIBC_RETVAL_FAILED;
    }

    pak->addr_family = pak_info->addr_family;
    *pak_hdl = pak;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pak_destroy (olibc_pak_hdl *pak_hdl) 
{
    olibc_retval_t retval;

    if (!pak_hdl) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    retval = olibc_list_insert_node(pak_list_hdl, NULL, *pak_hdl);
    *pak_hdl = NULL;
//    olibc_free((void **)pak_hdl);
    return retval;
}

olibc_retval_t
olibc_pak_recv (olibc_pak_hdl pak_hdl, int fd, uint32_t offset_bytes)
{
    struct iovec iov;
    uint32_t data_len;
    uint8_t *data_buff = NULL;
    struct msghdr rmsghdr;
    struct cmsghdr *rcmsgp;
    uint32_t msg_controllen = 0;
    u_char cmsgbuf4[CMSG_SPACE(sizeof(struct in_pktinfo))];
    u_char cmsgbuf6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    socklen_t sock_addr_len = sizeof(struct sockaddr_storage);

    if (!pak_hdl || (fd < 0 )) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    memset(&rmsghdr, 0, sizeof(rmsghdr)); 
    memset(&iov, 0, sizeof(iov));

    if (pak_hdl->addr_family == AF_INET) {
        rcmsgp = (struct cmsghdr *)cmsgbuf4;
        rcmsgp->cmsg_level = IPPROTO_IP;
        rcmsgp->cmsg_type = IP_PKTINFO;
        rcmsgp->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

        rmsghdr.msg_name = (caddr_t) &pak_hdl->src_sock_addr;
        rmsghdr.msg_namelen = sizeof(struct sockaddr_in);
    } else if (pak_hdl->addr_family == AF_INET6) {
        rcmsgp = (struct cmsghdr *)cmsgbuf6;
        rcmsgp->cmsg_level = IPPROTO_IPV6;
        rcmsgp->cmsg_type = IPV6_PKTINFO;
        rcmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

        rmsghdr.msg_name = (caddr_t) &pak_hdl->src_sock_addr;
        rmsghdr.msg_namelen = sizeof(struct sockaddr_in6);
    }


    data_buff = pak_hdl->data_buf;
    data_buff += offset_bytes;

    iov.iov_base = data_buff;
    iov.iov_len = OLIBC_MAX_PAK_BUF_SIZE-offset_bytes;

    rmsghdr.msg_iov = &iov;
    rmsghdr.msg_iovlen = 1;
    rmsghdr.msg_control = (caddr_t) rcmsgp;
    rmsghdr.msg_controllen = msg_controllen;


    data_len = recvmsg(fd, &rmsghdr, 0);

    if (!data_len) {
        olibc_log_debug("\nNo data available in socket %d",fd);
        return OLIBC_RETVAL_NO_MORE_DATA;
    }

    data_len += offset_bytes;

    pak_hdl->data_set_flags |= OLIBC_PAK_INITED;

    if (sock_addr_len) {
        char addrstr[OLIBC_MAX_ADDR_STR];
        struct sockaddr *src_sock_addr = NULL;
        uint32_t src_port = 0, in_ifindex = 0;

        pak_hdl->data_set_flags |= OLIBC_SRC_SOCKADDR_SET;

        src_sock_addr = (struct sockaddr *)&pak_hdl->src_sock_addr;

        if (src_sock_addr->sa_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)src_sock_addr;
            src_port = ntohs(s->sin_port);
            inet_ntop(AF_INET, &s->sin_addr, addrstr, OLIBC_MAX_ADDR_STR);
        } else if (src_sock_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)src_sock_addr;
            src_port = ntohs(s->sin6_port);
            inet_ntop(AF_INET6, &s->sin6_addr, addrstr, OLIBC_MAX_ADDR_STR);
            in_ifindex = ntohl(s->sin6_scope_id);
            pak_hdl->in_ifindex = in_ifindex;
            if (in_ifindex) {
                pak_hdl->data_set_flags |= OLIBC_IN_IFHNDL_SET;
            }
        }
        olibc_log_debug("\nInIfIndex %d Src IP address: %s, Port: %d",
                        in_ifindex, addrstr, src_port);
    }

    for (rcmsgp = CMSG_FIRSTHDR(&rmsghdr);
         rcmsgp != NULL;
         rcmsgp = CMSG_NXTHDR(&rmsghdr, rcmsgp)) {
        if (rcmsgp->cmsg_level == IPPROTO_IP && 
            rcmsgp->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *dst_in4_pkt_info = NULL;
            struct sockaddr_in *s = NULL;
            dst_in4_pkt_info = (struct in_pktinfo *)CMSG_DATA(rcmsgp);
            s = (struct sockaddr_in *)&pak_hdl->dst_sock_addr;
            memcpy(&s->sin_addr, &dst_in4_pkt_info->ipi_addr,
                   sizeof(struct in_addr));
            s->sin_family = AF_INET;
            if (dst_in4_pkt_info->ipi_ifindex) {
                pak_hdl->in_ifindex = dst_in4_pkt_info->ipi_ifindex;
                pak_hdl->data_set_flags |= OLIBC_IN_IFHNDL_SET;
            }
        }

        if (rcmsgp->cmsg_level == IPPROTO_IPV6 && 
            rcmsgp->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo *dst_in6_pkt_info = NULL;
            struct sockaddr_in6 *s = NULL;

            dst_in6_pkt_info = (struct in6_pktinfo *)CMSG_DATA(rcmsgp);
            s = (struct sockaddr_in6 *)&pak_hdl->dst_sock_addr;
            memcpy(&s->sin6_addr, &dst_in6_pkt_info->ipi6_addr,
                   sizeof(struct in_addr));
            if ((pak_hdl->data_set_flags & OLIBC_IN_IFHNDL_SET) &&
                (pak_hdl->in_ifindex != dst_in6_pkt_info->ipi6_ifindex)) {
                olibc_log_error("\nIN ifIndex mismatch");
            }
            if (dst_in6_pkt_info->ipi6_ifindex) {
                pak_hdl->in_ifindex = dst_in6_pkt_info->ipi6_ifindex;
                pak_hdl->data_set_flags |= OLIBC_IN_IFHNDL_SET;
            }
            s->sin6_family = AF_INET6;
        }
    }
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pak_send (olibc_pak_hdl pak_hdl,  int fd, uint32_t offset_bytes)
{
    char *data_buff = NULL;
    struct iovec iov;
    struct msghdr smsghdr;
    struct cmsghdr *scmsgp;
    uint32_t msg_controllen = 0;
    u_char cmsgbuf4[CMSG_SPACE((int)sizeof(struct in_pktinfo))];
    u_char cmsgbuf6[CMSG_SPACE((int)sizeof(struct in6_pktinfo))];
    uint32_t data_sent = 0;

    memset(&smsghdr, 0, sizeof(smsghdr)); 
    memset(&iov, 0, sizeof(iov));
    memset(cmsgbuf4, 0, CMSG_SPACE(sizeof(struct in_pktinfo)));
    memset(cmsgbuf6, 0, CMSG_SPACE(sizeof(struct in6_pktinfo)));

    if (!pak_hdl || (fd < 0 )) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if (pak_hdl->data_set_flags & OLIBC_DST_SOCKADDR_SET) {
        smsghdr.msg_name = (caddr_t) &pak_hdl->dst_sock_addr;
        if (pak_hdl->dst_sock_addr.ss_family == AF_INET) {
            smsghdr.msg_namelen = sizeof(struct sockaddr_in);
        }
         
        if (pak_hdl->dst_sock_addr.ss_family == AF_INET6) {
            smsghdr.msg_namelen = sizeof(struct sockaddr_in6);
            if (pak_hdl->data_set_flags & OLIBC_OUT_IFHNDL_SET) {
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)
                    &pak_hdl->dst_sock_addr;
                s6->sin6_scope_id = pak_hdl->out_ifindex;
            }
        }
    }
            
    if (pak_hdl->data_set_flags & 
        (OLIBC_OUT_IFHNDL_SET | OLIBC_SRC_SOCKADDR_SET)) {
        if (pak_hdl->addr_family == AF_INET) {
            scmsgp = (struct cmsghdr *)cmsgbuf4;
            scmsgp->cmsg_level = IPPROTO_IP;
            scmsgp->cmsg_type = IP_PKTINFO;
            scmsgp->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

        } else if (pak_hdl->addr_family == AF_INET6) {
            struct in6_pktinfo *dst_in6_pkt_info = NULL;
            
            scmsgp = (struct cmsghdr *)cmsgbuf6;

            scmsgp->cmsg_level = IPPROTO_IPV6;
            scmsgp->cmsg_type = IPV6_PKTINFO;
            scmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

            dst_in6_pkt_info = (struct in6_pktinfo *)CMSG_DATA(scmsgp);
            dst_in6_pkt_info->ipi6_ifindex = pak_hdl->out_ifindex;

            if (pak_hdl->data_set_flags & OLIBC_SRC_SOCKADDR_SET) { 
                struct sockaddr_in6 *s6 = 
                    (struct sockaddr_in6 *)&pak_hdl->dst_sock_addr;
                memcpy(&dst_in6_pkt_info->ipi6_addr, &s6->sin6_addr,
                       sizeof(struct in6_addr)); 
            }

            if (pak_hdl->data_set_flags & OLIBC_OUT_IFHNDL_SET) {
                if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &pak_hdl->out_ifindex,
                            sizeof(pak_hdl->out_ifindex)) < 0) {
                    olibc_log_error("\nFailed to set IPv6 Out IfIndex");
                    return OLIBC_RETVAL_FAILED;
                }
            }
        }
    }


    data_buff =  pak_hdl->data_buf + offset_bytes;
    iov.iov_base = data_buff;
    iov.iov_len = pak_hdl->data_length - offset_bytes;

    smsghdr.msg_iov = &iov;
    smsghdr.msg_iovlen = 1;
    smsghdr.msg_controllen = msg_controllen;
    if (msg_controllen) { 
        smsghdr.msg_control = (caddr_t) scmsgp;
    }

    data_sent = sendmsg(fd, &smsghdr, 0);
    if (data_sent != iov.iov_len) {
        olibc_log_error("\nFailed to send data %d - %d", 
                (int)iov.iov_len, data_sent);
        return OLIBC_RETVAL_FAILED;
    }

    return OLIBC_RETVAL_SUCCESS;
}


olibc_retval_t
olibc_pak_get_data_buffer (olibc_pak_hdl pak_hdl, 
                           uint8_t **data_buff, uint32_t *data_len)
{
    if (!pak_hdl || !(pak_hdl->data_set_flags & OLIBC_PAK_INITED)) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if (data_buff) {
        *data_buff = pak_hdl->data_buf;
    }

    if (data_len) {
        *data_len = pak_hdl->data_length;
    }
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pak_set_out_if_index (olibc_pak_hdl pak_hdl,
                           uint32_t if_index)
{
    if (!pak_hdl) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    pak_hdl->out_ifindex = if_index;
    pak_hdl->data_set_flags |= OLIBC_OUT_IFHNDL_SET;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pak_get_in_if_index (olibc_pak_hdl pak_hdl,
                           uint32_t *if_index)
{
    if (!pak_hdl || 
        !(pak_hdl->data_set_flags & OLIBC_PAK_INITED) || 
        !if_index) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    if (!pak_hdl->data_set_flags & OLIBC_IN_IFHNDL_SET) {
        return OLIBC_RETVAL_NO_MATCHING_DATA;
    }
    *if_index =  pak_hdl->in_ifindex;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pak_get_src_addr (olibc_pak_hdl pak_hdl,
                        struct sockaddr_storage *sock_addr)
{
    if (!pak_hdl || 
        !(pak_hdl->data_set_flags & OLIBC_PAK_INITED) || 
        !sock_addr) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    if (!(pak_hdl->data_set_flags & OLIBC_SRC_SOCKADDR_SET)) {
        return OLIBC_RETVAL_NO_MATCHING_DATA;
    }
    memcpy(sock_addr, &pak_hdl->src_sock_addr, sizeof(struct sockaddr_storage));

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pak_get_dst_addr (olibc_pak_hdl pak_hdl,
                        struct sockaddr_storage *sock_addr)
{
    if (!pak_hdl || 
        !(pak_hdl->data_set_flags & OLIBC_PAK_INITED) || 
        !sock_addr) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    if (!(pak_hdl->data_set_flags & OLIBC_DST_SOCKADDR_SET)) {
        return OLIBC_RETVAL_NO_MATCHING_DATA;
    }
    memcpy(sock_addr, &pak_hdl->dst_sock_addr, sizeof(struct sockaddr_storage));

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pak_set_src_addr (olibc_pak_hdl pak_hdl,
                        struct sockaddr *sock_addr)
{
    uint32_t bytes_to_copy = 0;

    if (!pak_hdl) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    pak_hdl->data_set_flags |= OLIBC_DST_SOCKADDR_SET;

    if (sock_addr->sa_family == AF_INET) {
        bytes_to_copy = sizeof(struct sockaddr_in);
    }

    if (sock_addr->sa_family == AF_INET6)  {
        bytes_to_copy = sizeof(struct sockaddr_in6);
    }

    if (!bytes_to_copy) {
        olibc_log_error("\nUnrecognized address family socket");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    memcpy(&pak_hdl->src_sock_addr, sock_addr, bytes_to_copy);

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pak_set_dst_addr (olibc_pak_hdl pak_hdl,
                        struct sockaddr *sock_addr)
{
    uint32_t bytes_to_copy = 0;

    if (!pak_hdl) {
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    pak_hdl->data_set_flags |= OLIBC_DST_SOCKADDR_SET;

    if (sock_addr->sa_family == AF_INET) {
        bytes_to_copy = sizeof(struct sockaddr_in);
    }

    if (sock_addr->sa_family == AF_INET6)  {
        bytes_to_copy = sizeof(struct sockaddr_in6);
    }

    if (!bytes_to_copy) {
        olibc_log_error("\nUnrecognized address family socket");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    memcpy(&pak_hdl->dst_sock_addr, sock_addr, bytes_to_copy);

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_pak_set_length (olibc_pak_hdl pak_hdl,
                      uint32_t data_length)
{
    if (!pak_hdl) { 
        olibc_log_error("\nInvalid input");
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    pak_hdl->data_length = data_length;
    return OLIBC_RETVAL_SUCCESS;
}
