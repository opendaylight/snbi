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

#include <olibc_pak.h>

typedef struct olibc_pak_t_ an_pak_linux_t;

boolean an_linux_sock_create(void);

#endif
