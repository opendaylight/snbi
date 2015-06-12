/**
  * Vijay Anand R <vanandr@cisco.com>
  *
  */
#include <stdio.h>
#include <string.h>
#include <cparser.h>
#include <olibc_if.h>
#include <cparser_tree.h>

cparser_result_t 
cparser_cmd_test_if_list (cparser_context_t *context)
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
    return CPARSER_OK;
}
