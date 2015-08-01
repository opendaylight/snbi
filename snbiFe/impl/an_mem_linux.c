/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_avl.h>
#include <an_logger.h>
#include <an_mem_guard.h>
#include <an_mem.h>

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
an_memset_guard_s (void *target, uint8_t num, uint32_t length)
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
    if (an_chunk) {
        an_chunk->chunk_size = chunk_size;
        an_chunk->chunkpool_size = chunkpool_size;
        an_chunk->chunkpool_id = chunkpool_id;
        an_chunk->refcount = 0;
    }
    return (an_chunk);
}

boolean 
an_mem_chunkpool_destroyable (an_mem_chunkpool_t *chunkpool)
{
    return (chunkpool->refcount == 0);
}

boolean 
an_mem_chunkpool_destroy (an_mem_chunkpool_t *chunkpool)
{
    if (chunkpool) {
        free(chunkpool);
    }
    return (TRUE);
}

void *
an_mem_chunk_malloc (an_mem_chunkpool_t *chunkpool)
{
    void *element = NULL;

    if (!chunkpool) { 
        return NULL;
    } 

//    element = malloc((chunkpool->chunkpool_size) +
  //                  (chunkpool->chunk_size));
    element = malloc(chunkpool->chunk_size);
    if (!element) {
        return NULL;
    }
    memset(element, 0, chunkpool->chunk_size);
    chunkpool->refcount++;
    return (element);
}

void
an_mem_chunk_free (an_mem_chunkpool_t **chunkpool, void *buffer)
{
    if (buffer) {    
        (*chunkpool)->refcount--;
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

void
an_memcpy_guard_s (void *target, uint32_t dest_len, 
                   void *source, uint32_t src_len) 
{
    int len;

    len = dest_len;
    if (dest_len != src_len) {
        printf("\nan_memcpy_guard_s src len and dest len are not the same");
        len = dest_len > src_len ? src_len:dest_len;
    }
    memcpy(target, source, len);
}

an_errno 
an_memcpy_s(void *dest, an_rsize dmax, const void *src, an_rsize smax)
{
    memcpy(dest, src, dmax);
    return EOK;
}

an_errno 
an_memset_s(void *dest, uint8_t value, an_rsize len) 
{

    memset(dest, value, len);
    return EOK;
}

an_errno 
an_memcmp_s(const void *dest, an_rsize dmax, const void *src,
                an_rsize smax, int *diff)
{
    int len;

    *diff = -1;
    if (dest == src) {
        *diff = 0;
        return EOK;
    }

    len = dmax;
    if (dmax != smax) {
        len = dmax > smax ? smax : dmax;
    }

    *diff = memcmp(dest, src, len);
    return EOK;
}


