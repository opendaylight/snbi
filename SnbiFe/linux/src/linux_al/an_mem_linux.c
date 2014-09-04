/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_types.h"
#include "an_avl.h"
#include "an_logger.h"
#include "an_mem_guard.h"
#include "an_mem.h"

void 
an_memcpy_guard (void *target, void *source, uint32_t length)
{
    memcpy(target, source, length);
    return;
}

void 
an_memcpy (void *target, void *source, uint32_t length)
{
    memcpy(target, source, length);
    return;
}

void 
an_memset_guard (void *target, uint8_t num, uint32_t length)
{
    memset(target, num, length);
    return;
}

void 
an_memset (void *target, uint8_t num, uint32_t length)
{
    memset(target, num, length);
    return;
}

uint32_t 
an_memcmp (void *target, void *source, uint32_t length)
{
    return (memcmp(target, source, length));
}

an_mem_chunkpool_t *
an_mem_chunkpool_create (uint16_t chunk_size, uint16_t chunkpool_size,
                         uint8_t *chunkpool_id)
{
    an_mem_chunkpool_t *an_chunk = NULL;
    an_chunk = malloc (sizeof(an_mem_chunkpool_t));
    an_chunk->chunk_size = chunk_size;
    an_chunk->chunkpool_size = chunkpool_size;
    an_chunk->chunkpool_id = chunkpool_id;
    return (an_chunk);
}

boolean 
an_mem_chunkpool_destroyable (an_mem_chunkpool_t *chunkpool)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}

boolean 
an_mem_chunkpool_destroy (an_mem_chunkpool_t *chunkpool)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}

void *
an_mem_chunk_malloc (an_mem_chunkpool_t *chunkpool)
{
    if (chunkpool) { 
        return ((void *)malloc(chunkpool->chunk_size));
    } else {
        return NULL;
    }
}

void
an_mem_chunk_free (an_mem_chunkpool_t **chunkpool, void *buffer)
{
    if (buffer) {    
        free(buffer);
    }    
    return;
}

void *
an_malloc (uint32_t size, uint8_t* name)
{
        return (malloc(size));
}

void
an_free (void *buffer)
{
    if (buffer) {    
       free(buffer);
    }   
}

void *
an_malloc_guard (uint32_t size, uint8_t* name)
{
        return (malloc(size));
}

void
an_free_guard (void *buffer)
{
    if (buffer) {    
        free(buffer);
    }    
}
