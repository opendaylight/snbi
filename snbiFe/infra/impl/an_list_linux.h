/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_LIST_LINUX_H__
#define __AN_LIST_LINUX_H__

#include "an_types.h"

/*
 * Flag defines for list
 */
#define LIST_FLAGS_NONE           0x0000
#define LIST_FLAGS_VALID          0x0001
#define LIST_FLAGS_MALLOC         0x0002
#define LIST_FLAGS_AUTOMATIC      0x0004

typedef struct an_list_element_ an_list_element_t;
typedef struct an_list_header_  an_list_t;

struct an_list_header_
{
    void              *lock;
    an_list_element      *head;
    an_list_element      *tail;
    unsigned short     flags;
    unsigned long      count;
    unsigned long      maximum;
    char              *name;
};

struct an_list_element_ {
    an_list_t *list;
    an_list_element_t *next;
    an_list_element_t *prev;

    void *data;
};

struct an_list_ {
    an_list_element_t *head;
    an_list_element_t *tail;
};
