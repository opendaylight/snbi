/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <string.h>
#include <stdlib.h>
#include <olibc_common.h>
#include "olibc_list_internal.h"

olibc_retval_t
olibc_list_create (olibc_list_t **list, 
                const char *list_name)
{
    olibc_list_t *new_list = NULL;
    olibc_retval_t retval;

    if ((retval= olibc_malloc((void**)&new_list, sizeof(olibc_list_t), 
                             __THIS_FUNCTION__)) != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    if (!new_list) {
        return (OLIBC_RETVAL_MEM_ALLOC_FAILED);
    }

    new_list->count   = 0;
    new_list->head    = NULL;
    new_list->tail    = NULL;
    new_list->name = strdup(list_name);
    *list = new_list;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_list_destroy (olibc_list_t **list, olibc_list_free_node_handler free_hdlr)
{
    olibc_list_element_hdl elem_hdl = NULL;
    void *data = NULL;
    boolean is_empty = TRUE;

    if (!list || !(*list)) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    } 

    while ((olibc_list_is_empty(*list, &is_empty) == OLIBC_RETVAL_SUCCESS )
            && !is_empty) {
        if (free_hdlr) {
            if (olibc_list_get_head_elem(*list, &elem_hdl) ==
                        OLIBC_RETVAL_SUCCESS) {
                    if (olibc_list_get_data(elem_hdl, &data) ==
                            OLIBC_RETVAL_SUCCESS) {
                        free_hdlr(data);
                    }
            }
        }
        olibc_list_dequeue_node(*list, NULL);
    }
    free((*list)->name);
    olibc_free((void **)list);
    *list = NULL;
    return (OLIBC_RETVAL_SUCCESS);
}

olibc_retval_t
olibc_list_is_valid (olibc_list_t *list, boolean *is_valid)
{
    if (!is_valid) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    *is_valid = list ? TRUE : FALSE;
    return (OLIBC_RETVAL_SUCCESS);
}

olibc_retval_t
olibc_list_is_empty (olibc_list_t *list, boolean *is_empty)
{   
    if (!list) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    *is_empty = (list->head ? FALSE : TRUE);
    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_list_lookup_node (olibc_list_t *list,
                        void* data, olibc_list_comp_handler comp_handler,
                        void **return_data)
{
   void *elem_data = NULL;
   olibc_list_element_t *element = NULL;
   int ret;
    
   if (!list || !comp_handler || !data) {
       return OLIBC_RETVAL_INVALID_INPUT;
   }
   
   OLIBC_FOR_ALL_DATA_IN_LIST(list, element, elem_data) {
       ret = comp_handler(elem_data, data);
       if (ret == 0) {
           /* Match found */    
           *return_data = data;
           return (OLIBC_RETVAL_SUCCESS);
       }
   }

   return (OLIBC_RETVAL_NO_MATCHING_DATA);
}

olibc_retval_t
olibc_list_insert_node (olibc_list_t *list, 
                         olibc_list_insert_comp_handler compare_func,
                         void  *data) 
{
    olibc_list_element_t *new_element = NULL;
    olibc_list_element_t *current = NULL;
    olibc_list_element_t *prev_elem = NULL;
    olibc_retval_t retval;
    
    if ((list == NULL) || (data == NULL)) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }
    
    if ((retval= olibc_malloc((void **)&new_element, 
                              sizeof(olibc_list_element_t), 
                             __THIS_FUNCTION__)) != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    if (!new_element) {
        return (OLIBC_RETVAL_MEM_ALLOC_FAILED);
    }

    new_element->data = data; 
    current = list->tail;
    if (!current) { 
        /* Insert new element at the head of the list */
        new_element->next = list->head;
        list->head = new_element;
        new_element->prev = NULL; 
    } else  {
        if (compare_func) {
            current = list->head;
            while (current) {
                if (!compare_func(data, current->data)) {
                    break;
                }
                prev_elem = current;
                current = current->next;
            }
            current = prev_elem;
        }
        /* Insert new after the current*/
        new_element->next = current->next;
        current->next = new_element;
        new_element->prev = current;
    }
    /*
     * If we're not the tail, attach the backpointer
     */
    if (new_element->next) {
        new_element->next->prev = new_element;
    }
    /*
     * If this is the tail, update the pointer.
     */
    if (current == list->tail) {
        list->tail = new_element;
    }     

    new_element->list = list;
    new_element->list->count++;
    return (OLIBC_RETVAL_SUCCESS);
}

olibc_retval_t
olibc_list_dequeue_node (olibc_list_t *list, void **return_data)
{
    olibc_retval_t retval;
    olibc_list_element_t *element = NULL;
    void *data = NULL;


    if (list == NULL) { 
        return (OLIBC_RETVAL_INVALID_INPUT); 
    } 

    if (return_data) {
        *return_data = NULL;
    }
    retval = olibc_list_get_head_elem(list, &element);    
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }
    
    retval = olibc_list_get_data(element, &data); 
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    retval = olibc_list_remove_node(list, NULL,
            data, NULL, return_data);

    if (retval != OLIBC_RETVAL_SUCCESS)  {
        return (retval);
    }

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_list_remove_node (olibc_list_t *list,
                        olibc_list_element_t *element,
                        void *data,
                        olibc_list_comp_handler comp_handler,
                        void **return_data)
{
    void *elem_data = NULL;
    int ret = 0;

    if (!list || !data) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    if (!element) {
        // No user element found find it.
        OLIBC_FOR_ALL_DATA_IN_LIST(list, element, elem_data) {
            if (comp_handler) {
                ret = comp_handler(elem_data, data); 
                if (ret == 0) {
                    /* Match found */    
                    break;
                }
            } else if (data == elem_data) {
                // Just compare the pointers.
                break;
            }
        }
    }

    if ((element->list != list) || (element->data != data)) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }     
    if (element->next) {
        element->next->prev = element->prev;
    }

    if (element->prev) {
        element->prev->next = element->next;
    }

    if (element == list->head) {
       list->head = element->next;
    }

    if (element == list->tail) {
       list->tail = element->prev;
    }

    if (return_data) {
        *return_data = element->data;
    }

    element->list->count--;
    element->next = element->prev = NULL;
    element->list = NULL;
    olibc_free((void **)element);

    return (OLIBC_RETVAL_SUCCESS);
}  

olibc_retval_t
olibc_list_get_head_elem (olibc_list_t *list, olibc_list_element_t **elem)
{
    boolean is_empty = TRUE;

    if (!list || !elem) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    *elem = NULL;
    if ((olibc_list_is_empty(list, &is_empty) == OLIBC_RETVAL_SUCCESS) 
            && !is_empty) {
        *elem = list->head;
        return (OLIBC_RETVAL_SUCCESS);
    }
    return (OLIBC_RETVAL_EMPTY_DATA_SET);
}

olibc_retval_t
olibc_list_get_data (olibc_list_element_t *elem, 
                     void **return_data)
{
    if (!elem) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    } 
    *return_data = elem->data;
    return (OLIBC_RETVAL_SUCCESS);
}

olibc_retval_t 
olibc_list_walk (olibc_list_t *list, 
                 olibc_list_walk_handler func,
                 void *context)
{   
    olibc_list_element_t *runner = NULL, *next = NULL;
    int ret_val = 0;

    if (!list || !func) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }     

    OLIBC_FOR_ALL_ELEMENTS_IN_LIST_SAVE_NEXT(list, runner, next) {
        ret_val = (*func)(list, runner, next, context);
        if(ret_val) {
           // The user returned some non-zero value, break and return
           break;
        } 
    }
    return 0;
}

olibc_retval_t
olibc_list_iterator_create (olibc_list_hdl list_hdl, 
                            olibc_list_iterator_hdl *hdl) 
{
    olibc_retval_t retval;
    olibc_list_element_hdl elem_hdl = NULL;
    struct olibc_list_iterator_t_ *iter = NULL;

    if (!list_hdl || !iter) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    if ((retval= olibc_malloc((void **)&iter, sizeof(olibc_list_iterator_t), 
                             __THIS_FUNCTION__)) != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }
    iter->list_hdl = list_hdl;
    iter->curr_elem_hdl = NULL;

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_list_iterator_get_next (olibc_list_iterator_hdl iter,
                              void **return_data)
{
    olibc_retval_t retval;
    olibc_list_element_t *next_elem = NULL;
    olibc_list_element_hdl elem_hdl = NULL;

    if (!iter || !iter->list_hdl) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    if (!iter->curr_elem_hdl) {
        retval = olibc_list_get_head_elem(iter->list_hdl, &elem_hdl);
        next_elem = elem_hdl;
        if (!next_elem) {
            return (OLIBC_RETVAL_EMPTY_DATA_SET);
        }
    } else  {
        next_elem = iter->curr_elem_hdl->next;
        if (!next_elem) {
           return (OLIBC_RETVAL_NO_MORE_DATA);
        }
    }

    iter->curr_elem_hdl = next_elem;
    retval = olibc_list_get_data(next_elem, return_data);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return retval;
    }

    return OLIBC_RETVAL_SUCCESS;
}

olibc_retval_t
olibc_list_iterator_destory (olibc_list_iterator_hdl *iter)
{
    if (!iter || !*iter) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }

    olibc_free((void **)iter);
    *iter = NULL;
    return OLIBC_RETVAL_SUCCESS;
}
