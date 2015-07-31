/**
  * Vijay Anand R <vanandr@cisco.com>
  *
  */
#include <stdio.h>
#include <string.h>
#include <cparser.h>
#include <olibc_if.h>
#include <olibc_addr.h>
#include <cparser_tree.h>
#include <arpa/inet.h>

cparser_result_t 
cparser_cmd_test_interface_list (cparser_context_t *context)
{
    olibc_if_info_t if_info;
    olibc_if_iterator_filter_t filter;
    olibc_if_iterator_hdl if_iter_hdl;
    olibc_retval_t retval;

    retval = olibc_if_iterator_create(&filter, &if_iter_hdl);

    printf("\nif iterator create returned %s", olibc_retval_get_string(retval));
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return CPARSER_OK;
    }

    memset(&if_info, 0, sizeof(if_info));
    while (olibc_if_iterator_get_next(if_iter_hdl, &if_info) ==
            OLIBC_RETVAL_SUCCESS) {
        printf("\ninterface name: %s", if_info.if_name);
        printf("\nIndex : %d", if_info.if_index);
        printf("\nif_state : %s",if_info.if_state == IF_UP ? 
                "IF_UP":"IF_DOWN");
        printf("\nis loopback: %s",if_info.is_loopback ? "Yes":"No");
        printf("\nhw addr len: %d", if_info.hw_addr_len);
        printf("\nhw addr: %02x:%02x:%02x:%02x:%02x:%02x",
                if_info.hw_addr[0] & 0xff, if_info.hw_addr[1] & 0xff,
                if_info.hw_addr[2] & 0xff, if_info.hw_addr[3] & 0xff,
                if_info.hw_addr[4] & 0xff, if_info.hw_addr[5] & 0xff);
        printf("\n");
        memset(&if_info, 0, sizeof(if_info));
    }
    printf("\nIf iterator destroy returned %s",
           olibc_retval_get_string(olibc_if_iterator_destroy(&if_iter_hdl)));
    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_test_interface_ip_address (cparser_context_t *context)
{ 
    uint32_t if_index;
    olibc_retval_t retval;
    olibc_addr_info_t addr_info;
    char ip_str[INET6_ADDRSTRLEN];
    olibc_addr_iterator_hdl iter_hdl;
    olibc_addr_iterator_filter_t filter;

    filter.flags |= (OLIBC_FLAG_IPV4 | OLIBC_FLAG_IPV6);
    retval = olibc_addr_iterator_create(&filter, &iter_hdl);
    printf("\nAddr iterator create returned %s",
            olibc_retval_get_string(retval));

    if (retval != OLIBC_RETVAL_SUCCESS) { 
        return CPARSER_OK;
    }
    memset(&addr_info, 0, sizeof(olibc_addr_info_t));
    while (olibc_addr_iterator_get_next(iter_hdl, &addr_info, &if_index)
            == OLIBC_RETVAL_SUCCESS) {
        printf("\nif_index %d", if_index);
        if (addr_info.addr_family == AF_INET) {
            inet_ntop(addr_info.addr_family, &addr_info.addrv4, ip_str,
                    sizeof(ip_str));
        }
        if (addr_info.addr_family == AF_INET6) {
            inet_ntop(addr_info.addr_family, &addr_info.addrv6, ip_str,
                     sizeof(ip_str));
        }
        printf("\nIP address %s/%d",ip_str, addr_info.prefixlen);
        printf("\n");
        memset(&addr_info, 0, sizeof(olibc_addr_info_t));
    }
    printf("\nIf iterator destroy returned %s",
           olibc_retval_get_string(olibc_addr_iterator_destroy(&iter_hdl)));
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_interface_ipv6_address (cparser_context_t *context)
{
    uint32_t if_index;
    olibc_retval_t retval;
    olibc_addr_info_t addr_info;
    char ip_str[INET6_ADDRSTRLEN];
    olibc_addr_iterator_hdl iter_hdl;
    olibc_addr_iterator_filter_t filter;

    filter.flags |= OLIBC_FLAG_IPV6;
    retval = olibc_addr_iterator_create(&filter, &iter_hdl);
    printf("\nAddr iterator create returned %s",
            olibc_retval_get_string(retval));

    if (retval != OLIBC_RETVAL_SUCCESS) { 
        return CPARSER_OK;
    }
    memset(&addr_info, 0, sizeof(olibc_addr_info_t));
    while (olibc_addr_iterator_get_next(iter_hdl, &addr_info, &if_index)
            == OLIBC_RETVAL_SUCCESS) {
        printf("\nif_index %d", if_index);
        if (addr_info.addr_family == AF_INET) {
            inet_ntop(addr_info.addr_family, &addr_info.addrv4, ip_str,
                    sizeof(ip_str));
        }
        if (addr_info.addr_family == AF_INET6) {
            inet_ntop(addr_info.addr_family, &addr_info.addrv6, ip_str,
                     sizeof(ip_str));
        }
        printf("\nIP address %s/%d",ip_str, addr_info.prefixlen);
        printf("\n");
        memset(&addr_info, 0, sizeof(olibc_addr_info_t));
    }
    printf("\nIf iterator destroy returned %s",
           olibc_retval_get_string(olibc_addr_iterator_destroy(&iter_hdl)));
    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_test_interface_ipv4_address (cparser_context_t *context)
{
    uint32_t if_index;
    olibc_retval_t retval;
    olibc_addr_info_t addr_info;
    char ip_str[INET6_ADDRSTRLEN];
    olibc_addr_iterator_hdl iter_hdl;
    olibc_addr_iterator_filter_t filter;

    filter.flags |= (OLIBC_FLAG_IPV4);
    retval = olibc_addr_iterator_create(&filter, &iter_hdl);
    printf("\nAddr iterator create returned %s",
            olibc_retval_get_string(retval));

    if (retval != OLIBC_RETVAL_SUCCESS) { 
        return CPARSER_OK;
    }
    memset(&addr_info, 0, sizeof(olibc_addr_info_t));
    while (olibc_addr_iterator_get_next(iter_hdl, &addr_info, &if_index)
            == OLIBC_RETVAL_SUCCESS) {
        printf("\nif_index %d", if_index);
        if (addr_info.addr_family == AF_INET) {
            inet_ntop(addr_info.addr_family, &addr_info.addrv4, ip_str,
                    sizeof(ip_str));
        }
        if (addr_info.addr_family == AF_INET6) {
            inet_ntop(addr_info.addr_family, &addr_info.addrv6, ip_str,
                     sizeof(ip_str));
        }
        printf("\nIP address %s/%d",ip_str, addr_info.prefixlen);
        printf("\n");
        memset(&addr_info, 0, sizeof(olibc_addr_info_t));
    }
    printf("\nIf iterator destroy returned %s",
           olibc_retval_get_string(olibc_addr_iterator_destroy(&iter_hdl)));
    return CPARSER_OK;
}
