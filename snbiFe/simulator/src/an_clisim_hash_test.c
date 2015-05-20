/**
  * Vijay Anand R <vanandr@cisco.com>
  *
  */
#include <an_list.h>
#include <stdio.h> 
#include <stdlib.h>
#include "an_types.h"
#include <cparser.h>
#include <olibc_hash.h>
#include <cparser_tree.h>
#include <string.h>

olibc_hash_hdl test_hash_hdl;

static int
test_hash_free_data_func (void *data)
{
    printf("\nfree : %s",(char *)data);
    free(data);
    return 0;
}

cparser_result_t 
cparser_cmd_test_hash_create (cparser_context_t *context)
{
    olibc_retval_t retval;
    olibc_hash_info_t hash_info;

    memset(&hash_info, 0, sizeof(olibc_hash_info_t));

    hash_info.size = 15;
    hash_info.algorithm_type = OLIBC_HASH_ELF;
    hash_info.free_data_func = test_hash_free_data_func;

    retval = olibc_hash_create(&test_hash_hdl, &hash_info);

    printf("Hash creation %s\n", retval == OLIBC_RETVAL_SUCCESS ? "Success" :
            "Failed");
    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_test_hash_destory (cparser_context_t *context)
{
    olibc_retval_t retval;

    retval = olibc_hash_destroy(&test_hash_hdl);

    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_hash_insert_key_value (cparser_context_t *context,
                                        char **key_ptr,
                                        char **value_ptr)
{
    olibc_retval_t retval;
    char *key;
    char *value;

    key = *key_ptr;
    value = strdup(*value_ptr);

    retval = olibc_hash_insert_node(test_hash_hdl, value, key, strlen(key));

    printf("Hash insert %s\n",olibc_retval_get_string(retval));

    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_test_hash_lookup_key(cparser_context_t *context, char **key_ptr)
{
    olibc_retval_t retval;
    char *ret_data = NULL;
    char *key = *key_ptr;

    retval = olibc_hash_lookup_node(test_hash_hdl, (void **) &ret_data,(void
                *)key, strlen(key));

    printf("Hash lookup %s\n",olibc_retval_get_string(retval));

    printf("Data: %s\n", ret_data ? ret_data:"NULL");
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_hash_remove_key (cparser_context_t *context,
                                  char **key_ptr)
{
    olibc_retval_t retval;
    char *return_data = NULL;

    retval = olibc_hash_remove_node(test_hash_hdl, 
                                    (void **)&return_data, 
                                    *key_ptr,
                                    strlen(*key_ptr));

    printf("Hash remove node %s\n", olibc_retval_get_string(retval));

    printf(" value %s\n", return_data ? return_data:"NULL");
    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_test_hash_walk (cparser_context_t *context)
{
    olibc_retval_t retval;
    olibc_hash_iterator_hdl iter_hdl;
    char *return_value = NULL, *return_key = NULL;
    uint32_t key_len;

    retval = olibc_hash_iterator_create(test_hash_hdl, &iter_hdl);

    while (olibc_hash_iterator_get_next(iter_hdl, 
                                         (void **)&return_value, 
                                         (void **)&return_key, 
                                         &key_len) == OLIBC_RETVAL_SUCCESS) {
        printf("Key: %-10s(%d) - Value: %s\n", 
                return_key, key_len, return_value);
    }
    return CPARSER_OK;
}
