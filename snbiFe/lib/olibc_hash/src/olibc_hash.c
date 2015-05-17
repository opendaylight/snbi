/**
  */
#include <string.h>
#include <stdlib.h>
#include "olibc_hash_internal.h"

#define OLIBC_DEFAULT_HASH_TABLE_SIZE 10

static uint32_t
olibc_elf_hash_gen (char* str, uint32_t len)
{
   uint32_t hash = 0;
   uint32_t x    = 0;
   uint32_t i    = 0;

   for(i = 0; i < len; str++, i++) {
      hash = (hash << 4) + (*str);
      if((x = hash & 0xF0000000L) != 0)
      {
         hash ^= (x >> 24);
      }
      hash &= ~x;
   }
   return hash;
}

static olibc_list_cbk_return_t
hash_node_compare_func (void *insert_data, void *list_data)
{
    int strcmp_ret = 0;
    olibc_hash_node_t *insert_node = NULL, *list_node = NULL;
    uint32_t key_length_bytes = 0;

    if (!insert_data || !list_data) {
        // Stop the walk something went wrong.
        return OLIBC_LIST_CBK_RET_STOP;
    }

    insert_node = insert_data;
    list_node = list_data;

    if (insert_node->hash_key > list_node->hash_key) {
        // Continue searching, not equal.  
        return OLIBC_LIST_CBK_RET_CONTINUE;
    }

    key_length_bytes = insert_node->key_length_bytes >
        list_node->key_length_bytes ? list_node->key_length_bytes :
        insert_node->key_length_bytes;

    strcmp_ret = strncmp(insert_node->key, list_node->key, key_length_bytes);

    if (strcmp == 0) {
        if (insert_node->key_length_bytes > list_node->key_length_bytes) {
            // More number of new node bytes continue.
            return (OLIBC_LIST_CBK_RET_CONTINUE);
        } 
        if (insert_node->key_length_bytes == list_node->key_length_bytes) { 
            return OLIBC_LIST_CBK_RET_EQUAL;
        }
        return OLIBC_LIST_CBK_RET_STOP;
    }

    if (strcmp_ret > 0) {
        return OLIBC_LIST_CBK_RET_CONTINUE;
    }

    if (strcmp_ret < 0) {
        return OLIBC_LIST_CBK_RET_STOP;
    }

    return OLIBC_LIST_CBK_RET_STOP;
}

static int 
hash_node_compare_func (void *data1, void *data2)
{
    olibc_hash_node_t *node1 = NULL, *node2 = NULL;
    uint32_t node_key_length;

    if (!data1 || !data2) {
        return -1;
    }

    node1 = (olibc_hash_node_t *)data1;
    node2 = (olibc_hash_node_t *)data2;

    if (node1->hash_key != node2->hash_key) {
        return 1;
    }

    if (node1->key_length_bytes != node2->key_length_bytes) {
        return 1;
    }

    node_key_length = node1->key_length_bytes;

    if (strncmp(node1->key, node2->key, node_key_length)) {
        return 1;
    }

    return 0;
}

olibc_retval_t
olibc_hash_create (olibc_hash_hdl *hash_hdl,
                   olibc_hash_info_t *hash_info)
{
    int i = 0;
    olibc_retval_t retval;
    olibc_hash_t *hash = NULL;
    olibc_list_hdl *list_hdls = NULL;

    if (!hash_hdl || !hash_info) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }
    
    if ((retval = olibc_malloc((void **)&hash,
                    sizeof(olibc_hash_t),  __THIS_FUNCTION__)) !=
            OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    if (!hash) {
        return OLIBC_RETVAL_FAILED;
    }

    if (hash_info->size) {
        hash->size = hash_info->size;
    } else {
        hash->size = OLIBC_DEFAULT_HASH_TABLE_SIZE;
    }

    switch (hash_info->algorithm_type) {
        case OLIBC_HASH_DEFAULT:
        case OLIBC_HASH_ELF:
            hash->gen_func = olibc_elf_hash_gen;
            break;
        case OLIBC_HASH_CUSTOM:
            if (hash_info->gen_func) {
                hash->gen_func = hash_info->gen_func;
            } else {
                retval = OLIBC_RETVAL_INVALID_INPUT;
                goto HASH_CREATE_CLEANUP;
            }
        default: 
            retval = OLIBC_RETVAL_INVALID_INPUT;
            goto HASH_CREATE_CLEANUP;
    }
    hash->free_data_func = hash_info->free_data_func;

    retval = olibc_malloc((void **)&list_hdls, 
            sizeof(olibc_list_hdl) * hash->size, 
            __THIS_FUNCTION__);

    if (retval != OLIBC_RETVAL_SUCCESS || !list_hdls) {
        goto HASH_CREATE_CLEANUP;
    }

    hash->list_hdls = list_hdls;
    while (i < hash->size) {
        if ((retval = olibc_list_create(&list_hdls[i], __THIS_FUNCTION__)) !=
                OLIBC_RETVAL_SUCCESS) {
            goto HASH_CREATE_CLEANUP;
        }
        i++;
    }

    *hash_hdl = hash;

    return (OLIBC_RETVAL_SUCCESS);

HASH_CREATE_CLEANUP:
    if (hash) {
        i = 0;
        list_hdls = hash->list_hdls;
        while (i < hash->size && list_hdls) {
            if (list_hdls[i]) {
                olibc_list_destroy(&list_hdls[i], 
                        (olibc_list_free_data_func_t)hash->free_data_func);
            }
            i++;
        }
        olibc_free((void **)&list_hdls);
        olibc_free((void **)&hash);
    }
    return retval;
}

int
olibc_hash_node_free_func (void *node)
{
    olibc_hash_node_t *hash_node = node;

    if (!node) {
        return FALSE;
    }

    if (hash_node->hash_hdl && hash_node->hash_hdl->free_data_func) {
        hash_node->hash_hdl->free_data_func(hash_node->data);
    }

    hash_node->data = NULL;
    free(hash_node->key);
    olibc_free((void **)&hash_node);
    return TRUE;
}

olibc_retval_t
olibc_hash_destroy (olibc_hash_hdl *hash_hdl)
{
    int i =0;
    olibc_list_hdl *list_hdls = NULL;
    olibc_hash_hdl hash = NULL;

    if (!hash_hdl || !*hash_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    hash = *hash_hdl;

    if (hash->ref_count) {
        hash->ref_count = hash->ref_count - 1;
        *hash_hdl = NULL;
        return OLIBC_RETVAL_SUCCESS;
    }

    list_hdls = hash->list_hdls;

    for (i = 0; i < hash->size; i++) {
        olibc_list_hdl list_hdl = list_hdls[i];
        olibc_list_destroy(&list_hdl, olibc_hash_node_free_func);
    }
    hash->list_hdls = NULL;
    *hash_hdl = NULL;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_hash_lookup_node (olibc_hash_hdl hash_hdl,
                        void **return_data, char *key,
                         uint32_t byte_length)
{
    olibc_retval_t retval;
    uint32_t hash_key;
    uint32_t list_index;
    olibc_list_hdl list_hdl;
    olibc_hash_node_t tmp_node, *node = NULL, *return_node = NULL;

    if (!hash_hdl || !key || !byte_length || !return_data) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    node = &tmp_node;

    hash_key = hash_hdl->gen_func(key, byte_length);

    list_index = hash_key % hash_hdl->size;

    list_hdl = hash_hdl->list_hdls[list_index];

    node->hash_hdl = hash_hdl;
    node->data = NULL;
    node->hash_key = hash_key;
    node->key_length_bytes = byte_length;
    node->key = key;

    retval = olibc_list_lookup_node(list_hdl, (void *) node,
                hash_node_compare_func, (void **)&return_node);

    *return_data = return_node->data;
    return retval;
}

olibc_retval_t
olibc_hash_insert_node (olibc_hash_hdl hash_hdl,
                         void *data, char *key,
                         uint32_t key_length_bytes)
{
    olibc_retval_t retval;
    uint32_t hash_key;
    uint32_t list_index;
    olibc_list_hdl list_hdl;
    olibc_hash_node_t *node = NULL, *return_node = NULL;

    if (!hash_hdl || !data || !key || !key_length_bytes) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    hash_key = hash_hdl->gen_func(key, key_length_bytes);

    list_index = hash_key % hash_hdl->size;

    list_hdl = hash_hdl->list_hdls[list_index];

    if ((retval = olibc_malloc((void **)&node,
                sizeof(olibc_hash_node_t), __THIS_FUNCTION__)) !=
        OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    node->hash_hdl = hash_hdl;
    node->data = data;
    node->hash_key = hash_key;
    node->key_length_bytes = key_length_bytes;
    node->key = strndup(key, key_length_bytes);

    retval = olibc_list_lookup_node(list_hdl, (void *) node,
                hash_node_compare_func, (void **)&return_node);

    if (retval != OLIBC_RETVAL_NO_MATCHING_DATA || return_node) {
        olibc_free((void **)&node);
        return (OLIBC_RETVAL_DUPLICATE_DATA);
    }

    if ((retval = olibc_list_insert_node(list_hdl, 
                                        hash_node_compare_func, 
                                        (void *)node)) != 
                                        OLIBC_RETVAL_SUCCESS) {
        olibc_free((void **)&node);
        return retval;
    }
    return retval;
}

olibc_retval_t
olibc_hash_remove_node (olibc_hash_hdl hash_hdl, 
                         void **return_data,
                         char *key, 
                         uint32_t key_length_bytes)
{
    void *data = NULL;
    olibc_retval_t retval;
    uint32_t hash_key, list_index;
    uint32_t min_key_length_bytes;
    olibc_hash_node_t tmp_node, *node = NULL, *return_node = NULL;
    olibc_list_hdl list_hdl = NULL;
    olibc_list_element_hdl elem_hdl = NULL;
    

    if (!hash_hdl || !key || !key_length_bytes) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    node = &tmp_node;

    hash_key = hash_hdl->gen_func(key, byte_length);

    list_index = hash_key % hash_hdl->size;

    list_hdl = hash_hdl->list_hdls[list_index];

    node->hash_hdl = hash_hdl;
    node->data = NULL;
    node->hash_key = hash_key;
    node->key_length_bytes = byte_length;
    node->key = key;

    return_node = NULL;
    retval = olibc_list_remove_node(list_hdl, NULL, 
                                    node, hash_node_compare_func,
                                    &return_node);

    if (return_node && return_data) {
        *return_data = return_node->data;
    }

    return retval;
}

olibc_retval_t
olibc_hash_iterator_create (olibc_hash_hdl hash_hdl, 
                            olibc_hash_iterator_hdl *iter_hdl)
{
    olibc_retval_t retval;
    olibc_hash_iterator_t *iter = NULL;

    if (!hash_hdl || !iter_hdl) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    retval = olibc_malloc((void **)&iter,
            sizeof(olibc_hash_iterator_t), __THIS_FUNCTION__);

    if (!iter || retval != OLIBC_RETVAL_SUCCESS) {
        return (retval != OLIBC_RETVAL_SUCCESS ? retval :
                OLIBC_RETVAL_MEM_ALLOC_FAILED);
    }

    iter->curr_index = 0;
    iter->hash = hash_hdl;
    hash_hdl->ref_count = hash_hdl->ref_count+1;
    *iter_hdl = iter;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_hash_iterator_destroy (olibc_hash_iterator_hdl *iter_hdl)
{
    olibc_hash_iterator_t *iter;
    if (!iter_hdl || !*iter_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    iter = *iter_hdl;

    if (iter->list_iter_hdl) {
        olibc_list_iterator_destroy(&iter->list_iter_hdl);
    }

    olibc_hash_destroy(&iter->hash);

    olibc_free((void **)iter_hdl);
    return (OLIBC_RETVAL_SUCCESS);
}

olibc_retval_t
olibc_hash_iterator_get_next (olibc_hash_iterator_hdl hash_iter_hdl,
                              void **return_data,
                              void **return_key,
                              uint32_t *key_len_bytes)
{
    int i = 0;
    olibc_retval_t retval;
    boolean is_empty = TRUE;
    olibc_list_hdl list_hdl = NULL;
    olibc_hash_node_t *hash_node = NULL;
    olibc_list_iterator_hdl list_iter_hdl = NULL;

    if (!hash_iter_hdl || !hash_iter_hdl->hash) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    if (hash_iter_hdl->list_iter_hdl) {
        list_iter_hdl = hash_iter_hdl->list_iter_hdl;
        retval = olibc_list_iterator_get_next(list_iter_hdl, 
                                              (void **)&hash_node);
        if (retval == OLIBC_RETVAL_SUCCESS) {
            if (return_data) {
                *return_data = hash_node->data;
            }
            if (return_key) {
                *return_key = strndup(hash_node->key, 
                                      hash_node->key_length_bytes);
            }
            if (key_len_bytes) {
                *key_len_bytes = hash_node->key_length_bytes;
            }
            return retval;
        }
        hash_iter_hdl->curr_index = hash_iter_hdl->curr_index + 1;
        olibc_list_iterator_destroy(&hash_iter_hdl->list_iter_hdl);
        hash_iter_hdl->list_iter_hdl = NULL;
    }

    for (i = hash_iter_hdl->curr_index;
         (i < hash_iter_hdl->hash->size) &&
         (list_hdl = hash_iter_hdl->hash->list_hdls[i]); i++) {
        olibc_list_is_empty(list_hdl, &is_empty);
        if (is_empty) {
            continue;
        }
        list_iter_hdl = NULL;
        if ((retval = olibc_list_iterator_create(list_hdl, &list_iter_hdl))
                != OLIBC_RETVAL_SUCCESS || !list_iter_hdl) {
            return (retval == OLIBC_RETVAL_SUCCESS ? 
                    OLIBC_RETVAL_FAILED : retval);
        }
        hash_iter_hdl->list_iter_hdl = list_iter_hdl;
        hash_iter_hdl->curr_index = i;
        hash_node = NULL;
        retval = olibc_list_iterator_get_next(list_iter_hdl, 
                                              (void **)&hash_node);
        if (retval != OLIBC_RETVAL_SUCCESS || !hash_node) {
            return (retval == OLIBC_RETVAL_SUCCESS ? 
                    OLIBC_RETVAL_FAILED : retval);
        } 
        if (return_data) {
            *return_data = hash_node->data;
        } 
        if (return_key) {
            *return_key = hash_node->key;
        }
        if (key_len_bytes) {
            *key_len_bytes = hash_node->key_length_bytes;
        }
        return OLIBC_RETVAL_SUCCESS;
    }
    return (OLIBC_RETVAL_NO_MORE_DATA);
}
