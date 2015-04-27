/**
  */
#include <olibc_hash_internal.h>

#define OLIBC_DEFAULT_HASH_TABLE_SIZE 10

static unsigned int 
olibc_elf_hash_gen (char* str, unsigned int len)
{
   unsigned int hash = 0;
   unsigned int x    = 0;
   unsigned int i    = 0;

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

static int 
hash_insert_compare_func (void *insert_data, void *list_data)
{
    olibc_hash_node_t *insert_node = NULL, *list_node = NULL;
    unsigned int key_length_bytes = 0;

    if (!insert_data || !list_data) {
        return FALSE;
    }

    insert_node = insert_data;
    list_node = list_data;

    if (insert_data->hash_key > list_data->hash_key) {
        // Continue to the next node.
        return TRUE;
    }
    key_length_bytes = insert_data->key_length_bytes >
        list_data->key_length_bytes ? list_data->key_length_bytes :
        insert_data->key_length_bytes;


    if (strncmp(insert_data->key, list_data->key, key_length_bytes) > 0) {
        return TRUE;
    }
    return FALSE;
}

static int 
hash_node_compare_func (void *data1, void *data2)
{
    olibc_hash_node_t *node1 = NULL, *node2 = NULL;
    unsigned int node_key_length;

    if (!data1 || !data2) {
        return FALSE;
    }

    node1 = (olibc_hash_node_t *)data1;
    node2 = (olibc_hash_node_t *)data2;

    if (node1->hash_key != node2->hash_key) {
        return FALSE;
    }

    node_key_length = node1->key_length_bytes > node2->key_length_bytes ?
        node2->key_length_bytes : node1->key_length_bytes;

    if (strncmp(node1->key, node2->key, node_key_length)) {
        return FALSE;
    }

    return TRUE;
}

olibc_retval_t
olibc_hash_create (olibc_hash_hdl *hash_hdl,
                   olibc_hash_info_t *hash_info)
{
    int i = 0;
    olibc_retval_t retval;
    olibc_hash_t *hash = NULL;
    olibc_list_hdl list_hdls[] = NULL;

    if (!hash_hdl || !hash_info) {
        return (OLIBC_API_RETVAL_FAILED);
    }
    
    if ((retval = olibc_malloc((void **)&hash,
                    sizeof(olibc_hash_t),  __FUNCTION__)) !=
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
        case OLIBC_CUSTOM:
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
    hash->free_func = hash_info->free_func;

    retval = olibc_malloc((void **)&list_hdls, 
            sizeof(olibc_list_hdl) * hash->size, 
            __FUNCTION__);

    if (retval != OLIBC_RETVAL_SUCCESS || !list_hdls) {
        goto HASH_CREATE_CLEANUP;
    }

    hash->list_hdls = list_hdls;
    while (i < hash->size) {
        if ((retval = olibc_list_create(&list_hdls[i], __FUNCTION__)) !=
                OLIBC_RETVAL_SUCCESS) {
            goto HASH_CREATE_CLEANUP;
        }
    }

    *hash_hdl = hash;

    return (OLIBC_RETVAL_SUCCESS);

HASH_CREATE_CLEANUP:
    if (hash) {
        i = 0;
        list_hdls = hash->list_hdls;
        while (i < hash->size && list_hdls) {
            if (list_hdls[i]) {
                olibc_list_destroy(&list_hdls[i]);
            }
            i++;
        }
        olibc_free(&list_hdls);
        olibc_free(&hash);
    }
    return retval;
}

olibc_retval_t
olibc_hash_insert_node (olibc_hash_hdl hash_hdl,
                         void *data, char *key,
                         unsigned int key_length_bytes)
{
    unsigned int hash_key;
    unsigned int list_index;
    olibc_hash_node_t *node = NULL, *return_node = NULL;
    olibc_list_hdl list_hdl;

    if (!hash_hdl || !data || !key || !key_length_bytes) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    hash_key = hash_hdl->gen_func(key, key_length_bytes);

    list_index = hash_key % hash_hdl->size;

    list_hdl = hash->hash_hdl[list_index];

    if (retval = olibc_malloc((void **)&node,
                sizeof(olibc_hash_node_t), __FUNCTION__) !=
        OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    node->data = data;
    node->hash_key = hash_key;
    node->key_length_bytes = key_length_bytes;
    node->key = strndup(key, key_length_bytes);

    if (retval = olibc_list_lookup_node(list_hdl, (void *) node,
                hash_node_compare_func, (void **)&return_node) 
                != OLIBC_RETVAL_SUCCESS) {
        olibc_free(&node);
        return retval;
    }

    if (return_node) {
        return (OLIBC_RETVAL_DUPLICATE_DATA);
    }

    if (retval = olibc_list_enqueue_node(list_hdl, 
                                  hash_insert_compare_func, (void *)
            node) != OLIBC_RETVAL_SUCCESS) {
        olibc_free(&node);
        return retval;
    }
    return retval;
}

olibc_retval_t
olibc_hash_remove_node (olibc_hash_hdl hash_hdl, 
                         void **return_data,
                         char *key, 
                         unsigned int key_length_bytes)
{
    olibc_retval_t retval;
    void *data = NULL, *return_data = NULL;
    unsigned int hash_key;
    unsigned int min_key_length_bytes;
    olibc_hash_node_t *node = NULL;
    olibc_list_hdl list_hdl = NULL;
    olibc_list_element_hdl elem_hdl = NULL;

    if (!return_data || !key || !key_length_bytes) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    hash_key = hash_hdl->gen_func(key, key_length_bytes);
    list_index = hash_key % hash_hdl->size;
    list_hdl = hash->hash_hdl[list_index];

    OLIBC_FOR_ALL_DATA_IN_LIST(list_hdl, elem_hdl, data) {
        node = (olibc_hash_node_t *)data;
        if (hash_key > node->hash_key) {
            continue;
        }

        if (hash_key < node->hash_key) {
            return (OLIBC_RETVAL_NO_MATCHING_DATA);
        }

        min_key_length_bytes = 
            node->key_length_bytes > key_length_bytes ?
            key_length_bytes : node->key_length_bytes;

        if (hash_key == node->hash_key && 
            strncmp(key, node->key, min_key_length_bytes)) {
            *return_data = node->data;
            retval = olibc_list_remove_node(list_hdl, elem_hdl, data, NULL);
            free(node->key);
            free(node);
            return retval;
        }
    }
}

olibc_retval_t
olibc_hash_iterator_create (olibc_hash_hdl hash_hdl, 
                            olibc_hash_iterator_hdl *iter_hdl)
{
    int i = 0;
    olibc_retval_t retval;
    olibc_hash_iterator_t *iter = NULL;

    if (!hash_hdl || !iter_hdl) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    retval = olibc_malloc((void **)&iter,
            sizeof(olibc_hash_iterator_t), __FUNCTION__);

    if (!iter || retval != OLIBC_RETVAL_SUCCESS) {
        return (retval != OLIBC_RETVAL_SUCCESS ? retval :
                OLIBC_RETVAL_MEM_ALLOC_FAILED);
    }

    iter->curr_index = 0;
    iter->hash = hash_hdl;
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
    olibc_free(iter_hdl);
    return (OLIBC_RETVAL_SUCCESS);
}

olibc_retval_t
olibc_hash_iterator_get_next (olibc_hash_iterator_hdl iter_hdl,
                              void **return_data);
{
    int i = 0;
    boolean is_empty = TRUE;
    olibc_retval_t retval;
    olibc_list_hdl list_hdl = NULL;
    olibc_hash_node_t *hash_node = NULL;
    olibc_list_iterator_hdl list_iter_hdl = NULL

    if (!iter_hdl || !return_data) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    if (iter_hdl->list_iter_hdl) {
        list_hdl = iter->list_iter_hdl;
        retval = olibc_list_iterator_get_next(list_hdl, &hash_node);
        if (retval == OLIBC_RETVAL_SUCCESS) {
            *return_data = hash_node->data;
            return retval;
        }
        iter_hdl->curr_index = iter_hdl->curr_index + 1;
        olibc_list_iterator_destroy(&iter->list_iter_hdl);
        iter->list_iter_hdl = NULL;
    }

    for (i = iter_hdl->curr_index ; 
         i < iter_hdl->hash->size && 
         list_hdl = iter_hdl->list_hdls[i] ; i++) {
        olibc_list_is_empty(list_hdl, &is_empty);
        if (is_empty) {
            continue;
        } 
        if ((retval = olibc_list_iterator_create(list_hdl, &list_iter_hdl))
                != OLIBC_RETVAL_SUCCESS) {
            return reval;
        }
        iter->list_iter_hdl = list_iter_hdl;
        iter_hdl->curr_index = i;
        olibc_list_iterator_get_next(list_hdl, &hash_node);
        *return_data = hash_node->data;
        return OLIBC_RETVAL_SUCCESS;
    }
    return (OLIBC_RETVAL_NO_MORE_DATA);
}
