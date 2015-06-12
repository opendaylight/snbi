#ifndef __OLIBC_LOG_H__
#define __OLIBC_LOG_H__

#define DEBUG_LOG 0

#define olibc_log_debug(...)                            \
    do {                                                \
        if (DEBUG_LOG) {                                \
            printf(__VA_ARGS__);                        \
        }                                               \
    } while (0)                                         \

#define olibc_log_error(...)                            \
    do {                                                \
        if (DEBUG_LOG_ERROR)                            \
            printf(__VA_ARGS);                          \
    } while (0)                                         \

#endif
