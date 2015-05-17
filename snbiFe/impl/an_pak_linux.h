/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_PAK_LINUX_H__
#define __AN_PAK_LINUX_H__

#include <an_types.h>
#include <an_types_linux.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

typedef struct an_pak_linux_t_ {
    uint8_t *data;
    uint32_t ifhndl;
    struct ip6_hdr ipv6_hdr; 
    uint8_t linktype;
    uint32_t datagramsize; 
} an_pak_linux_t;

void an_linux_pak_create(an_pak_linux_t *an_linux_pak, uint32_t ifhndl, char
        *data, struct sockaddr_storage *sender);
uint32_t an_get_ifhndl_from_sockaddr(struct sockaddr_storage *sender);

#endif
