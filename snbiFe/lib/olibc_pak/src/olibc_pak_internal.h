#ifndef __OLIBC_PAK_INTERNAL_H__
#define __OLIBC_PAK_INTERNAL_H__

#include <olibc_pak.h>
#include <sys/socket.h>

#define OLIBC_MAX_PAK_BUF_SIZE 5000

#define OLIBC_IN_IFHNDL_SET 0x01
#define OLIBC_OUT_IFHNDL_SET 0x02
#define OLIBC_SRC_SOCKADDR_SET 0x08
#define OLIBC_DST_SOCKADDR_SET 0x10
#define OLIBC_PAK_INITED 0x80

typedef struct olibc_pak_t_ {
    uint32_t max_pak_length;
    uint8_t data_set_flags;
    // UDP/TCP socket type.
    uint8_t data_buf[OLIBC_MAX_PAK_BUF_SIZE];
    uint32_t data_length;
    uint32_t in_ifindex;
    uint32_t out_ifindex;
    // IPv4/IPv6 address family.
    uint32_t addr_family;
    struct sockaddr_storage src_sock_addr;
    struct sockaddr_storage dst_sock_addr;
} olibc_pak_t;

#endif
