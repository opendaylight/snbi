/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "show_an.h"
#include "an_event_mgr.h"
#include "an_if_mgr.h"

void 
an_show_auton(bool no, int a, char *av[]) {
    uuid_t an_uuid = {0};
    int i;
    uuid_generate(an_uuid);
    printf ("\n UDI     ");
    for (i=0;i<sizeof (an_uuid); i++) {
        printf ("%x",an_uuid[i]);
    }
    printf("\n");
}

void an_show_auton_intf(bool no, int a, char *av[]) {
}

int 
an_show_intf(bool no, int a, char *av[]) 
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
        return 1;
    }

/* Query available interfaces. */
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if(ioctl(sck, SIOCGIFCONF, &ifc) < 0)
    {
        perror("ioctl(SIOCGIFCONF)");
        return 1;
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
            return 1;
        }

    /* Get the broadcast address */
        if(ioctl(sck, SIOCGIFBRDADDR, item) >= 0)
            printf(", BROADCAST %s", inet_ntoa(((struct sockaddr_in *)&item->ifr_broadaddr)->sin_addr));
        printf("\n");
    }
    close(sck); 
    return 0;
}

void an_show_proc(bool no, int a, char *av[]) {}

an_walk_e
an_if_info_walker(an_avl_node_t *node, void *data) {

     an_if_info_t *an_if_info = NULL;

    if (!node) {
        return (AN_WALK_FAIL);
    }
    an_if_info = *(an_if_info_t **)node;
    printf("\n ifhndl: %d", an_if_info->ifhndl);
    return (AN_WALK_SUCCESS);
}

int an_walk_if_db (bool no, int a, char *av[]) {
    an_if_info_db_walk(an_if_info_walker, NULL);
    return 0;
}
