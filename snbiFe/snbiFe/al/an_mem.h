/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_MEM_H__
#define __AN_MEM_H__

#include "an_types.h"
#include "../al/an_avl.h"

void an_memcpy_guard(void *target, void *source, uint32_t length);
void an_memset_guard(void *target, uint8_t num, uint32_t length);
void an_memcpy_guard_s(void *target, uint32_t dest_len, void *source, uint32_t src_len);
void an_memset_guard_s(void *target, uint8_t num, uint32_t length);
void an_memcpy(void *target, void *source, uint32_t length);
void an_memset(void *target, uint8_t num, uint32_t length);
uint32_t an_memcmp(void *target, void *source, uint32_t length);

an_mem_chunkpool_t * an_mem_chunkpool_create(uint16_t chunk_size, 
                                             uint16_t chunkpool_size,
                                             uint8_t *chunkpool_id);
boolean an_mem_chunkpool_destroyable(an_mem_chunkpool_t *chunkpool);
boolean an_mem_chunkpool_destroy(an_mem_chunkpool_t *chunkpool);
void *an_malloc_guard(uint32_t size, uint8_t *name);
void an_free_guard(void *buffer);
void *an_malloc(uint32_t size, uint8_t *name);
void an_free(void *buffer);
void * an_mem_chunk_malloc(an_mem_chunkpool_t *chunkpool);
void an_mem_chunk_free(an_mem_chunkpool_t **chunkpool, void *buffer);

void an_mem_elem_db_walk(an_avl_walk_f walk_func, void *args);
void an_mem_show(void);
an_errno an_memcpy_s(void *dest, an_rsize dmax, const void *src, an_rsize smax);
an_errno an_memset_s(void *dest, uint8_t value, an_rsize len);
an_errno an_memcmp_s(const void *dest, an_rsize dmax, const void *src,
                                                      an_rsize smax, int *diff);
an_errno an_memmove_s(void *dest, an_rsize dmax, const void *src, an_rsize smax);
an_mem_elem_t *an_mem_elem_db_search(void *buffer);
boolean an_mem_elem_db_insert(an_mem_elem_t *mem_elem);
boolean an_mem_elem_db_remove(an_mem_elem_t *mem_elem);

#endif
