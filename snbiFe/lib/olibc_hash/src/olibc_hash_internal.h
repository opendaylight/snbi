/**
  * 
  * Vijay Anand R <vanandr@cisco.com>
  */
#ifndef __OLIBC_HASH_INTERNAL_H__
#define __OLIBC_HASH_INTERNAL_H__

#include <olibc_hash.h>
#include <olibc_list.h>

typedef struct olibc_hash_t_ {
    olibc_hash_free_data_func_t free_data_func;
    olibc_hash_gen_func_t gen_func;
    uint32_t size;
    olibc_list_hdl *list_hdls;
    uint32_t ref_count;
} olibc_hash_t;

typedef struct olibc_hash_node_t_ {
    char *key;
    void *data;
    uint32_t hash_key;
    uint32_t key_length_bytes;
    olibc_hash_hdl hash_hdl;
} olibc_hash_node_t;

typedef struct olibc_hash_iterator_t_ {
    olibc_hash_hdl hash;
    uint32_t curr_index;
    olibc_list_iterator_hdl list_iter_hdl;
} olibc_hash_iterator_t;

#endif
