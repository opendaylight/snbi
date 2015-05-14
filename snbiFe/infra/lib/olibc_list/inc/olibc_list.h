/*
  *
  */
#ifndef __OLIBC_LIST_H__
#define __OLIBC_LIST_H__

#include <olibc_common.h>

typedef struct olibc_list_iterator_t_ *olibc_list_iterator_hdl; 

typedef struct olibc_list_element_t_ {
    struct olibc_list_header_t_ *list;
    struct olibc_list_element_t_ *next;
    struct olibc_list_element_t_ *prev;
    void *data;
} olibc_list_element_t;

typedef struct olibc_list_header_t_ {
    olibc_list_element_t *head;
    olibc_list_element_t *tail;
    unsigned long      count;
    char              *name;
} olibc_list_header_t;

typedef olibc_list_header_t olibc_list_t;
typedef olibc_list_header_t *olibc_list_hdl;
typedef olibc_list_element_t *olibc_list_element_hdl;

#define OLIBC_LIST_GET_DATA(__element) ((__element) ? (__element)->data : NULL)
#define OLIBC_LIST_HEAD_ELEMENT(__list) (__list)->head
#define OLIBC_LIST_NEXT_ELEMENT(__element) ((__element) ? (__element)->next: NULL)

#define OLIBC_LIST_NEXT_DATA(__element)      \
    (OLIBC_LIST_NEXT_ELEMENT(__element)) ? OLIBC_LIST_NEXT_ELEMENT(__element)->data : NULL
#define OLIBC_LIST_HEAD_DATA(__list)      \
    (OLIBC_LIST_HEAD_ELEMENT(__list)) ? OLIBC_LIST_HEAD_ELEMENT(__list)->data : NULL

#define OLIBC_ELEMENT_GET_LIST(__element) ((__element) ? (__element)->list : NULL)

#define OLIBC_FOR_ALL_DATA_IN_LIST(__list, __element, __data) \
  for (__element = OLIBC_LIST_HEAD_ELEMENT(__list),           \
       __data = OLIBC_LIST_GET_DATA(__element);               \
       __element != NULL;                                     \
       __element = OLIBC_LIST_NEXT_ELEMENT(__element),        \
       __data = OLIBC_LIST_GET_DATA(__element))

#define OLIBC_FOR_ALL_ELEMENTS_IN_LIST_SAVE_NEXT(__list, __element, __next)  \
  for ((__element)  = OLIBC_LIST_HEAD_ELEMENT((__list));                     \
       (__next) = OLIBC_LIST_NEXT_ELEMENT((__element)), (__element) != NULL; \
       (__element) = (__next))


typedef int (*olibc_list_comp_handler)(void *data1, void *data2);
typedef int (*olibc_list_insert_comp_handler)(void *insert_data, 
                                              void *list_data);
typedef int (*olibc_list_walk_handler)(olibc_list_hdl list_hdl,
                            const olibc_list_element_hdl current,
                            olibc_list_element_hdl next_hdl,
                            void *context);
typedef int (*olibc_list_free_node_handler)(void *data);


extern olibc_retval_t
olibc_list_create(olibc_list_hdl *hdl, const char *list_name);

extern olibc_retval_t
olibc_list_destroy(olibc_list_hdl *hdl, olibc_list_free_node_handler free_hdlr);

extern olibc_retval_t
olibc_list_lookup_node(olibc_list_hdl list_hdl, void* data, 
                       olibc_list_comp_handler comp_handler,
                       void **return_data);

extern olibc_retval_t
olibc_list_is_valid(olibc_list_hdl list_hdl, boolean *is_valid);

extern olibc_retval_t
olibc_list_is_empty(olibc_list_hdl list_hdl, boolean *is_empty);

extern olibc_retval_t
olibc_list_dequeue_node(olibc_list_hdl list_hdl, void **return_data);

extern olibc_retval_t
olibc_list_remove_node(olibc_list_hdl list_hdl, 
                       olibc_list_element_t *elem,
                       void *data,
                       olibc_list_comp_handler comp_handler, 
                       void **return_data);

extern olibc_retval_t
olibc_list_get_head_elem(olibc_list_hdl list_hdl, 
                         olibc_list_element_hdl *elem_hdl);

extern olibc_retval_t
olibc_list_get_data(olibc_list_element_hdl elem_hdl, void **data);

extern olibc_retval_t
olibc_list_walk(olibc_list_hdl list_hdl, olibc_list_walk_handler func,
                void *context);

extern olibc_retval_t
olibc_list_iterator_create(olibc_list_hdl list_hdl, 
                           olibc_list_iterator_hdl *iter);

extern olibc_retval_t
olibc_list_iterator_get_next(olibc_list_iterator_hdl iter,
                             void **return_data);

extern olibc_retval_t
olibc_list_iterator_destroy(olibc_list_iterator_hdl *iter);

extern olibc_retval_t
olibc_list_insert_node(olibc_list_hdl list_hdl,
                       olibc_list_insert_comp_handler compare_func,
                       void *data);

#endif //__OLIBC_LIST_H__
