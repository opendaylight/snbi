/**
  *
  */
#ifndef __OLIBC_COMMON_H__
#define __OLIBC_COMMON_H__

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

typedef bool boolean;

#define TRUE true
#define FALSE false

#define __THIS_FUNCTION__ (char *)__FUNCTION__

#define FOR_EACH_RETVAL_ENUM_GENERATOR(GENERATOR)                         \
    GENERATOR(OLIBC_RETVAL_MIN, "Minimum retval")                         \
    GENERATOR(OLIBC_RETVAL_SUCCESS, "Api returned success")               \
    GENERATOR(OLIBC_RETVAL_INVALID_INPUT, "API input is invalid")         \
    GENERATOR(OLIBC_RETVAL_FAILED, "API returned failure")                \
    GENERATOR(OLIBC_RETVAL_MEM_ALLOC_FAILED,                              \
            "API failed because of memory allocation failure")            \
    GENERATOR(OLIBC_RETVAL_EMPTY_DATA_SET,                                \
            "The collection has no data elements")                        \
    GENERATOR(OLIBC_RETVAL_DUPLICATE_DATA,                                \
            "The collection has already a data element")                  \
    GENERATOR(OLIBC_RETVAL_NO_MATCHING_DATA,                              \
            "The collection has no matching data element")                \
    GENERATOR(OLIBC_RETVAL_NO_MORE_DATA,                                  \
            "The iterator doesnt have any more data")                     \
    GENERATOR(OLIBC_RETVAL_MAX, "Max retval")

#define OLIBC_GENERATE_ENUM(ENUM,STRING) ENUM,

typedef enum olibc_retval_t_ {
    FOR_EACH_RETVAL_ENUM_GENERATOR(OLIBC_GENERATE_ENUM)
} olibc_retval_t;

extern const char* olibc_retval_get_string(olibc_retval_t retval);
extern olibc_retval_t olibc_malloc(void **block, uint32_t size, char *owner);
extern olibc_retval_t olibc_free(void **block);
extern olibc_retval_t olibc_memset(void *block, uint32_t val,  
                                   uint32_t size);

#endif //__OLIBC_COMMON_H__
