/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_LIST_LINUX_H__
#define __AN_LIST_LINUX_H__

#include <olibc_list.h>

typedef olibc_list_element_t an_list_element_t; 
typedef olibc_list_header_t an_list_t;

#define LIST_GET_DATA(element) OLIBC_GET_DATA(element)

#define LIST_HEAD_ELEMENT(list) OLIBC_HEAD_ELEMENT(list)

#define LIST_NEXT_ELEMENT(element) OLIBC_LIST_NEXT_ELEMENT(element)

#define LIST_NEXT_DATA(element) OLIBC_LIST_NEXT_DATA(element)

#define LIST_HEAD_DATA(list) OLIBC_LIST_HEAD_DATA(list)

#define ELEMENT_GET_LIST(element) OLIBC_ELEMENT_GET_LIST(element)  

#define AN_FOR_ALL_DATA_IN_LIST(_list, _element, _data) \
    OLIBC_FOR_ALL_DATA_IN_LIST(_list, _element, _data)

#define AN_FOR_ALL_ELEMENTS_IN_LIST_SAVE_NEXT(_list, _element, _next) \
    OLIBC_FOR_ALL_ELEMENTS_IN_LIST_SAVE_NEXT(_list, _element, _next)

#endif //__AN_LIST_LINUX_H__
