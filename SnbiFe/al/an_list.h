/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_LIST_TYPES_H__
#define __AN_LIST_TYPES_H__

#include "an_types.h"

typedef an_cerrno (*an_list_walk_handler)(an_list_t *list,
                    const an_list_element_t *current,
                    an_list_element_t *next,
                    void *context);
typedef int (*an_list_comp_handler)(void *data1, void *data2);

boolean an_list_is_valid(an_list_t *list);
boolean an_list_is_empty(an_list_t *list);
an_list_element_t* an_list_get_head_elem(an_list_t *list);
void* an_list_get_data(an_list_element_t *elem);

an_cerrno an_list_create(an_list_t **list, const char *list_name);
an_cerrno an_list_destroy(an_list_t **list);

void an_list_enqueue_node(an_list_t *list, void *data);
void* an_list_dequeue_node(an_list_t *list);
void* an_list_remove(an_list_t *list, an_list_element_t *element, void *data);
an_cerrno an_list_walk(an_list_t *list, an_list_walk_handler func, 
                     void *context);

void* an_list_lookup_node(an_list_t *list, an_list_element_t *elem,
                      void* data, an_list_comp_handler comp_handler);
#endif

