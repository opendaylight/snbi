/**
  * Vijay Anand R <vanandr@cisco.com>
  */

#include "olibc_common.h"

#define OLIBC_GENERATE_STRING(ENUM,STRING) STRING,

static const char *olibc_retval_strings[] = {
    FOR_EACH_RETVAL_ENUM_GENERATOR(OLIBC_GENERATE_STRING)
};

const char* olibc_retval_get_string (olibc_retval_t retval)
{
    if (retval < OLIBC_RETVAL_MIN || retval > OLIBC_RETVAL_MAX) {
        return ("Invalid api retval");
    }

    return olibc_retval_strings[retval];
}
