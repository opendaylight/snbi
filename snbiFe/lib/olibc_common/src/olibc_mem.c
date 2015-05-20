/**
  * Vijay Anand R <vanandr@cisco.com>
  */
#include <stdlib.h>
#include <string.h>
#include <olibc_common.h>

olibc_retval_t 
olibc_memset (void *block, uint32_t val, uint32_t size)
{
    if (!block) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }
    memset(block, val, size);

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_malloc (void **block, uint32_t size, char *owner)
{
    if (!block) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    *block = (void *)malloc(size);
    if (!*block) {
        return OLIBC_RETVAL_MEM_ALLOC_FAILED;
    }
    memset(*block, 0, size);
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_free (void **block)
{
    if (!block || !*block) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    free(*block);
    *block = NULL;
    return OLIBC_RETVAL_SUCCESS;
}
