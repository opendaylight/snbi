#include "olibc_common.h"

#define OLIBC_GENERATE_STRING(ENUM,STRING) STRING,

static const char *olibc_api_retval_strings[] = {
    FOR_EACH_RETVAL_ENUM_GENERATOR(OLIBC_GENERATE_STRING)
};

char* olibc_api_retval_get_string (olibc_api_retval_t retval)
{
    if (retval < OLIBC_RETVAL_MIN || retval > OLIBC_RETVAL_MAX) {
        return ("Invalid api retval");
    }

    return olibc_api_retval_strings[retval];
}
