/*
  *
  */
#ifndef __OLIBC_LIST_H__
#define __OLIBC_LIST_H__

#include <olibc_common.h>

typedef struct olibc_list_element_t_ {
    struct olibc_list_t_ *list;
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

#define OLIBC_GET_DATA(element) ((element) ? (element)->data : NULL)
#define OLIBC_HEAD_ELEMENT(list) (list)->head
#define OLIBC_LIST_NEXT_ELEMENT(element) ((element) ? (element)->next: NULL)

#define OLIBC_LIST_NEXT_DATA(element)      \
    (OLIBC_LIST_NEXT_ELEMENT(element)) ? OLIBC_LIST_NEXT_ELEMENT(element)->data : NULL
#define OLIBC_LIST_HEAD_DATA(list)      \
    (OLIBC_LIST_HEAD_ELEMENT(list)) ? OLIBC_LIST_HEAD_ELEMENT(list)->data : NULL

#define OLIBC_ELEMENT_GET_LIST(element) ((element) ? (element)->list : NULL)

#define OLIBC_FOR_ALL_DATA_IN_LIST(__list, __element, __data) \
  for (__element = OLIBC_LIST_HEAD_ELEMENT(__list),           \
       __data = OLIBC_LIST_GET_DATA(__element);               \
       __element != NULL;                               \
       __element = OLIBC_LIST_NEXT_ELEMENT(__element),        \
       __data = OLIBC_LIST_GET_DATA(__element))

#define OLIBC_FOR_ALL_ELEMENTS_IN_LIST_SAVE_NEXT(__list, __element, __next) \
  for ((__element)  = OLIBC_LIST_HEAD_ELEMENT((__list));                     \
       (__next) = OLIBC_LIST_NEXT_ELEMENT((__element)), (__element) != NULL;      \
       (__element) = (__next))


typedef int (*olibc_list_comp_handler)(void *data1, void *data2);
typedef int (*olibc_list_walk_handler)(olibc_list_t *list,
                            const olibc_list_element_t *current,
                            olibc_list_element_t *next,
                            void *context);


extern olibc_api_retval_t
olibc_list_new(olibc_list_t **list, const char *list_name);

extern olibc_api_retval_t
olibc_list_destroy(olibc_list_t **list);

extern olibc_api_retval_t
olibc_list_lookup_node(olibc_list_t *list, olibc_list_element_t *elem,
                       void* data, olibc_list_comp_handler comp_handler,
                       void **return_data);

extern olibc_api_retval_t
olibc_list_is_valid(olibc_list_t *list, bool *is_valid);

extern olibc_api_retval_t
olibc_list_is_empty(olibc_list_t *list, bool *is_empty);

extern olibc_api_retval_t
olibc_list_lookup_node(olibc_list_t *list, olibc_list_element_t *elem,
                       void* data, olibc_list_comp_handler comp_handler,
                       void **return_data);

extern olibc_api_retval_t
olibc_list_dequeue_node(olibc_list_t *list, void **return_data);

extern olibc_api_retval_t
olibc_list_remove_node(olibc_list_t *list, olibc_list_element_t *elem,
                       void *data, void **return_data);

extern olibc_api_retval_t
olibc_list_get_head_elem(olibc_list_t *list, olibc_list_element_t **elem);

extern olibc_api_retval_t
olibc_list_get_data(olibc_list_element_t *elem, void **data);

extern olibc_api_retval_t
olibc_list_walk(olibc_list_t *list, olibc_list_walk_handler func,
                void *context);

#endif //__OLIBC_LIST_H__
