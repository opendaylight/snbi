/**
  *
  */
#ifndef __OLIBC_COMMON_H__
#define __OLIBC_COMMON_H__

#include<stdbool.h>

#define FOR_EACH_RETVAL_ENUM_GENERATOR(GENERATOR)                              \
    GENERATOR(OLIBC_RETVAL_MIN, "Minimum retval")                              \
    GENERATOR(OLIBC_RETVAL_SUCCESS, "Api returned success")                    \
    GENERATOR(OLIBC_RETVAL_INVALID_INPUT, "API input is invalid")              \
    GENERATOR(OLIBC_RETVAL_FAILED, "API returned failure")                     \
    GENERATOR(OLIBC_RETVAL_EMPTY_DATA_SET,                                     \
            "The collection has no data elements")                             \
    GENERATOR(OLIBC_RETVAL_MAX, "Max retval")

#define OLIBC_GENERATE_ENUM(ENUM,STRING) ENUM,

typedef enum olibc_api_retval_t_ {
    FOR_EACH_RETVAL_ENUM_GENERATOR(OLIBC_GENERATE_ENUM)
} olibc_api_retval_t;

extern char* olibc_api_retval_get_string(olibc_api_retval_t retval);

#endif //__OLIBC_COMMON_H__
