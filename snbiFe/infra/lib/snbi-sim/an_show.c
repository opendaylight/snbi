/*
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


uint8_t an_table_header[81] = {[0 ... 79] = '-', [80] = '\0'};
uint8_t an_show_header[1] = {'\0'};
uint8_t an_show_trailer[1] = {'\0'};
static int link_count = 0;
extern an_info_t an_info;

static an_cerrno
an_show_nbr_list_name_cb (an_list_t *list,
        const an_list_element_t *current,
        an_list_element_t *next, void *context)
{
    an_nbr_link_spec_t *curr_data = NULL;
    uint8_t local_ifhndl[128] = {0};
    if (list && current)    {
        curr_data = (an_nbr_link_spec_t *) current->data;
        link_count ++;
        if_indextoname(curr_data->local_ifhndl, local_ifhndl);
        if (link_count == 1) {
                printf("%3s", local_ifhndl);
               
        } else {
                printf("\n%67s %30s","", local_ifhndl);
        }
        return (AN_CERR_SUCCESS);
    }
    return 1;
}

cparser_result_t 
cparser_cmd_show_snbi_device (cparser_context_t *context)
{
    int i;

    printf("\n%80s", an_show_header);
    printf ("\n UDI    %s ", an_info.udi.data);
    printf("\n%80s", an_show_trailer); 
}

cparser_result_t 
cparser_cmd_show_autonomic_interface(cparser_context_t *context)
{
}

cparser_result_t
cparser_cmd_show_ip_interfaces (cparser_context_t *context)
{
    char buf[1024];
    struct ifconf ifc;
    struct ifreq *ifr;
    int sck;
    int nInterfaces;
    int i;

/* Get a socket handle. */
    sck = socket(AF_INET, SOCK_DGRAM, 0);
    if(sck < 0)
    {
        perror("socket");
        return;
    }

/* Query available interfaces. */
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if(ioctl(sck, SIOCGIFCONF, &ifc) < 0)
    {
        perror("ioctl(SIOCGIFCONF)");
        return;
    }
/* Iterate through the list of interfaces. */
    ifr         = ifc.ifc_req;
    nInterfaces = ifc.ifc_len / sizeof(struct ifreq);
    for(i = 0; i < nInterfaces; i++)
    {
        struct ifreq *item = &ifr[i];

    /* Show the device name and IP address */
        printf("\n");
        printf("%s: IP %s",
               item->ifr_name,
               inet_ntoa(((struct sockaddr_in *)&item->ifr_addr)->sin_addr));

    /* Get the MAC address */
        if(ioctl(sck, SIOCGIFHWADDR, item) < 0)
        {
            perror("ioctl(SIOCGIFHWADDR)");
            return;
        }

    /* Get the broadcast address */
        if(ioctl(sck, SIOCGIFBRDADDR, item) >= 0)
            printf(", BROADCAST %s", inet_ntoa(((struct sockaddr_in *)&item->ifr_broadaddr)->sin_addr));
        printf("\n");
    }
    close(sck); 
    return;
}

cparser_result_t 
cparser_cmd_show_process (cparser_context_t *context)
{
}

an_avl_walk_e
an_show_nbr_command_cb (an_avl_node_t *node, void *data_ptr)
{
    an_nbr_t *nbr = (an_nbr_t *)node;
    uint8_t *unknown_str = "-";

    if (!nbr) {
        return (AN_AVL_WALK_FAIL);
    }
    printf("\n%s %32s %21s ",
           nbr->udi.data, nbr->device_id ? nbr->device_id : unknown_str,
           nbr->domain_id ? nbr->domain_id : unknown_str);

    an_nbr_link_db_walk(nbr->an_nbr_link_list,
                      an_show_nbr_list_name_cb, NULL);
    return TRUE;
}

cparser_result_t 
cparser_cmd_show_snbi_neighbors (cparser_context_t *context)
{
    printf("\n%80s", an_show_header);
    printf("\n%s %45s %21s %10s",
               "UDI", "Device-ID", "Domain", "Interface");
    printf("\n%80s", an_table_header);
    an_nbr_db_walk(an_show_nbr_command_cb, NULL);
    printf("\n%80s", an_show_trailer);
}

an_walk_e
an_if_info_walker(an_avl_node_t *node, void *data) 
{

    an_if_info_t *an_if_info = NULL;

    if (!node) {
        return (AN_WALK_FAIL);
    }
    an_if_info = (an_if_info_t *)node;
    printf("\nAVL walking nodes :\n");
    printf("\n Ifhndl while walk is %lu ", an_if_info->ifhndl); 
    printf("\n AN is auton enabled on interface ? ");
    (an_if_info->if_cfg_autonomic_enable > 0) ? printf("YES"):printf("NO");

    return (AN_WALK_SUCCESS);
}

cparser_result_t 
cparser_cmd_show_snbi_intf_db (cparser_context_t *context)
{
    an_if_info_db_walk(an_if_info_walker, NULL);
}

