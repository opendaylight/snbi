/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_MEM_GUARD_H__
#define __AN_MEM_GUARD_H__

#include "an_types.h"

#define AN_MEM_GUARD TRUE 
static const uint16_t AN_MEM_ELEM_POOL_SIZE = 64;

an_mem_elem_t* an_mem_elem_alloc(void);
void an_mem_elem_free(an_mem_elem_t *mem_elem);

void an_mem_show(void);
void an_mem_guard(void *target, uint16_t length);
void an_mem_guard_add(void *buffer, uint32_t size, uint8_t *name);
void an_mem_guard_remove(void *buffer);

#endif
