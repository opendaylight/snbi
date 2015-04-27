/*
  *
  */
#ifndef __OLIBC_LIST_H__

#define __OLIBC_LIST_H__

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


#endif //__OLIBC_LIST_H__
