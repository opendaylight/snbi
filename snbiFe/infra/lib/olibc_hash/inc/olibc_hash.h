/**
  *
  */

#ifndef __OLIBC_HASH_H__
#define __OLIBC_HASH_H__

typedef struct olibc_hash_t_ *olibc_hash_hdl;
typedef struct olibc_hash_iterator_t_ *olibc_hash_iterator_hdl;

typedef int (olibc_hash_gen_funct_t *) (char *key, unsigned int bytes);
typedef void (olibc_hash_value_free_func_t *) (void *value);

typedef enum olibc_hash_algorithm_e_ {
    OLIBC_HASH_DEFAULT,
    OLIBC_HASH_CUSTOM,
    OLIBC_HASH_ELF,
    OLIBC_HASH_MAX
} olibc_hash_algorithm_e;

typedef struct olibc_hash_info_t_ {
    uint32_t size;
    olibc_hash_gen_func_t gen_func;
    olibc_hash_value_free_func_t free_value_func;
    olibc_hash_algorithm_e algorithm_type;
} olibc_hash_info_t;

extern olibc_retval_t 
olibc_hash_create(olibc_hash_hdl *hash_hdl,
                  olibc_hash_info_t *hash_info);

extern olibc_retval_t
olibc_hash_destroy(olibc_hash_hdl hash_hdl);
                  
extern olibc_retval_t
olibc_hash_lookup_node(olibc_hash_hdl hash_hdl,
                       void **return_data, char *key, 
                       unsigned int byte_length);

extern olibc_retval_t
olibc_hash_insert_node(olibc_hash_hdl hash_hdl,
                        void **return_data, 
                        char *key,
                        unsigned int byte_length);
extern olibc_retval_t
olibc_hash_remove_node(olibc_hash_hdl hash_hdl,
                        void **return_data,
                        char *key,
                        unsigned int byte_length);


extern olibc_retval_t
olibc_hash_iterator_create(olibc_hash_hdl hash_hdl,
                           olibc_hash_iterator_hdl *iter);

extern olibc_retval_t
olibc_hash_iterator_get_next(olibc_hash_iterator_hdl iter,
                             void **return_data);

extern olibc_retval_t
olibc_hash_iterator_destory(olibc_hash_iterator_hdl *iter);

#endif
