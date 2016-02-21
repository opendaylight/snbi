/*
 * Vijay Anand R <vanandr@cisco.com>
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <stdio.h>
#include "an_event_mgr.h"
#include "an_if_mgr.h"
#include <cparser.h>
#include <cparser_tree.h>
#include <unistd.h>
#include <an.h>
#include <an_cert.h>
#include <an_addr.h>
#include <an_str.h>
#include <an_logger_linux.h>
#include <an_if.h>
#include <an_if_mgr.h>
#include <an_if_linux.h>

extern olibc_list_hdl an_if_linux_list_hdl;

uint8_t an_table_header[81] = {[0 ... 79] = '-', [80] = '\0'};
uint8_t an_show_header[1] = {'\0'};
uint8_t an_show_trailer[1] = {'\0'};

static an_cerrno
an_show_nbr_list_name_cb (an_list_t *list,
        const an_list_element_t *current,
        an_list_element_t *next, void *context)
{
    an_nbr_link_spec_t *curr_data = NULL;
    uint8_t if_name[80] = {0};
    if (list && current)    {
        curr_data = (an_nbr_link_spec_t *) current->data;
        if_indextoname(curr_data->local_ifhndl, if_name);
        printf("|%-7.7s", if_name);
        if (next) {
            printf("\n%72s","");
        }
        return (AN_CERR_SUCCESS);
    }
    return 1;
}

cparser_result_t 
cparser_cmd_show_snbi_device (cparser_context_t *context)
{
    char udi_str[80];
    an_addr_t device_ip = an_get_device_ip();
    an_cert_t domain_cert;
    uint8_t *device_id = NULL, *domain_id = NULL;
    an_udi_t udi;

    memset(udi_str, 0 , 80);
    memset(&domain_cert, 0 , sizeof(an_cert_t));
    memset(&udi, 0, sizeof(an_udi_t));

    if (!an_get_udi(&udi)) {
        return CPARSER_OK;
    }
    strncpy(udi_str, udi.data, udi.len > 80 ? 80 :udi.len);

    an_get_domain_cert(&domain_cert);
    device_id = an_get_device_id();
    domain_id = an_get_domain_id();

    printf("%80s", an_show_header);
    printf ("\n\t\t%-25s - %s ", "Device UDI",udi_str);
    if (device_id && an_strlen(device_id)) {
        printf("\n\t\t%-25s - %s", "Device ID", device_id);
    }

    if (domain_id && an_strlen(domain_id)) {
        printf("\n\t\t%-25s - %s", "Domain ID", domain_id);
    }
    if (domain_cert.data && domain_cert.len) {
        printf("\n\t\t%-25s - ", "Domain Certificate");
            an_cert_short_print(domain_cert);
    }
    if (domain_cert.data && domain_cert.len) {
        printf("\n\t\t%-25s - ", "Certificate Serial Number");
            an_cert_serial_num_print(domain_cert);
    }
    if (!an_addr_is_zero(device_ip)) {
        printf("\n\t\t%-25s - %s", "Device Address",
               an_addr_get_string(&device_ip));
    }
    if (domain_cert.valid) {
        printf("\n\t\t%-25s ", "Domain Cert is Valid");
    } else {
        printf("\n\t\t%-25s ", "Domain Cert is Not Valid");
    }

    printf("\n%80s", an_show_trailer); 
    printf("\n");

    return (CPARSER_OK);
}

an_avl_walk_e
an_show_nbr_command_cb (an_avl_node_t *node, void *data_ptr)
{
    an_nbr_t *nbr = (an_nbr_t *)node;

    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }
    printf("\n%-35.35s|%-20.20s|%-15.15s",
           nbr->udi.data, 
           nbr->device_id ? nbr->device_id : (uint8_t *)"         --",
           nbr->domain_id ? nbr->domain_id : (uint8_t *)"       -- ");

    an_nbr_link_db_walk(nbr->an_nbr_link_list,
                      an_show_nbr_list_name_cb, NULL);
    return TRUE;
}

cparser_result_t 
cparser_cmd_show_snbi_neighbors (cparser_context_t *context)
{
    printf("%80s", an_show_header);
    printf("\n%-35s|%-20s|%-15s|%-7s",
               "                 UDI", 
               "      Device-ID", "     Domain", "  Intf");
    printf("\n%80s", an_table_header);
    an_nbr_db_walk(an_show_nbr_command_cb, NULL);
    printf("\n%80s", an_show_trailer);
    printf("\n");
    return (CPARSER_OK);
}

cparser_result_t 
cparser_cmd_show_snbi_debugs (cparser_context_t *context)
{
    an_debug_log_show();
    printf("\n");
    return (CPARSER_OK);
}

cparser_result_t 
cparser_cmd_show_snbi_certificate_ca (cparser_context_t *context) 
{
    an_cert_t ca_cert;

    ca_cert = an_get_ca_cert();
    an_cert_display (ca_cert);
    return CPARSER_OK;
}
cparser_result_t 
cparser_cmd_show_snbi_certificate_device (cparser_context_t *context)
{
    an_cert_t device_cert;

    if(!an_get_domain_cert(&device_cert)) {
        return CPARSER_OK;
    }
    an_cert_display (device_cert);
    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_show_snbi_certificate_all(cparser_context_t *context)
{
    cparser_cmd_show_snbi_certificate_ca(context);
    cparser_cmd_show_snbi_certificate_device(context);
    return CPARSER_OK;
}

void
an_show_if_db (an_if_info_t *an_if_info)
{
    printf("\n");
    printf("%13s(%3d)  |", an_if_get_name(an_if_info->ifhndl), 
            an_if_info->ifhndl);
    printf("    %10s         |",an_if_info->autonomically_created ? "YES":"NO");
    printf("    %6s    |", an_if_info->if_cfg_autonomic_enable ? "YES":"NO");
    printf(" %s", an_if_info->nd_oper == AN_ND_OPER_UP ? "OPER UP":"OPER DOWN");
}

an_avl_walk_e
an_show_if_db_cb (an_avl_node_t *node, void *data)
{
    an_if_info_t *an_if_info = NULL;

    if (!node) {
        return (AN_AVL_WALK_FAIL);
    }

    an_if_info = (an_if_info_t *)node;

    an_show_if_db(an_if_info);

    return (AN_AVL_WALK_SUCCESS);
}

cparser_result_t
cparser_cmd_show_snbi_if_db (cparser_context_t *context)
{
    printf("%80s\n", an_show_header);
    printf("      If Info       | Autonomically Created | SNBI Enabled | ND OPER");
    printf("\n%80s", an_table_header);
    an_if_info_db_walk(an_show_if_db_cb, NULL);
    printf("\n");
    return CPARSER_OK;
}

void print_system_if_db ()
{
    olibc_retval_t retval;
    an_if_linux_info_t *if_linux_info = NULL;
    olibc_list_iterator_hdl if_list_iter = NULL;

    retval = olibc_list_iterator_create(an_if_linux_list_hdl, &if_list_iter);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return;
    }
    while (olibc_list_iterator_get_next(if_list_iter,
                                        (void **)&if_linux_info) ==
            OLIBC_RETVAL_SUCCESS) {
	printf("\n %-15s(%d) |", if_linux_info->if_name, if_linux_info->if_index);
    }
    olibc_list_iterator_destroy(&if_list_iter);
    return;
}

cparser_result_t cparser_cmd_show_system_if_db(cparser_context_t *context)
{
    print_system_if_db();
    printf("\n");
    return CPARSER_OK;
}
