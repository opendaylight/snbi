/**
  * Vijay Anand R <vanandr@cisco.com>
  */
#ifndef __OLIBC_LIST_INTERNAL_H__
#define __OLIBC_LIST_INTERNAL_H__

#include <olibc_list.h>

typedef struct olibc_list_iterator_t_ {
    olibc_list_hdl list_hdl;
    olibc_list_element_hdl curr_elem_hdl;
} olibc_list_iterator_t;

#endif
