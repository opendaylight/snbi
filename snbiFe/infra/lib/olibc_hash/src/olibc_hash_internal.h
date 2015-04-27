/**
  *
  */
#ifndef __OLIBC_HASH_INTERNAL_H__
#define __OLIBC_HASH_INTERNAL_H__

typedef struct olibc_hash_t_ {
    olibc_hash_value_free_func_t free_value_func;
    olibc_hash_get_func_t gen_func;
    uint32_t size;
    olibc_list_hdl list_hdls[];
} olib_hash_t;

typedef struct olibc_hash_node_t_ {
    void *data;
    char *key;
    unsigned int key_length_bytes;
    unsigned int hash_key;
} olibc_hash_node_t;

typedef struct olibc_hash_iterator_t_ {
    olibc_hash_t *hash;
    uint32_t curr_index;
    olibc_list_iterator_hdl list_iter_hdl;
} olibc_hash_iterator_t;
