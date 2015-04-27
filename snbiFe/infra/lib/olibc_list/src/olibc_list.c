/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <olibc_common.h>

olibc_api_retval_t
olibc_list_new (olibc_list_t **list, 
                const char *list_name)
{
    olibc_list_t *new_list = NULL;
    new_list = (olibc_list_t *)malloc(sizeof(olibc_list_t));
    if (!new_list) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    memset(new_list, 0, sizeof(olibc_list_t));
    new_list->count   = 0;
    new_list->head    = NULL;
    new_list->tail    = NULL;
    new_list->maximum = 0;
    new_list->name = list_name;
    *list = new_list;
    return OLIBC_RETVAL_SUCCESS;
}

olibc_api_retval_t
olibc_list_destroy (olibc_list_t **list)
{
    if (!list || !(*list)) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    } 

    while (!olibc_list_is_empty(*list)) {
        olibc_list_dequeue_node(*list);
    }
    free(*list);
    *list = NULL;
    return (OLIBC_RETVAL_SUCCESS);
}

olibc_api_retval_t
olibc_list_is_valid (olibc_list_t *list, boolean *is_valid)
{
    if (!is_valid) {
        return OLIBC_RETVAL_INVALID_INPUT;
    }
    *is_valid = list ? TRUE:FALSE;
    return (OLIBC_RETVAL_SUCCESS);
}

olibc_api_retval_t
olibc_list_is_empty (olibc_list_t *list, boolean *is_empty)
{   
    return (list->head ? FALSE : TRUE);
}

olibc_api_retval_t
olibc_list_lookup_node (olibc_list_t *list, olibc_list_element_t *elem,
                        void* data, olibc_list_comp_handler comp_handler,
                        void **return_data)
{
   void *runner = NULL;
   olibc_list_element_t *element = NULL;
   int ret;
    
   if (!list || !comp_handler || !data) {
       return OLIBC_RETVAL_INVALID_INPUT;
   }
   
   OLIBC_FOR_ALL_DATA_IN_LIST(list, element, runner) {
       ret = comp_handler(runner, data);
       if (ret == 0) {
           /* Match found */    
           *return_data = data;
           return (OLIBC_RETVAL_SUCCESS)
       }
   }

   return (NULL);
}

olibc_api_retval_t
olibc_list_enqueue_node (olibc_list_t *list, void  *data) 
{
    olibc_list_element_t *new_element = NULL;
    olibc_list_element_t *current = NULL;
    
    if ((list == NULL) || (data == NULL)) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }
    
    new_element = (olibc_list_element_t *)malloc(sizeof(olibc_list_element_t));
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
    } else {
    /* Insert new after current */
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

olibc_api_retval_t
olibc_list_dequeue_node (olibc_list_t *list, void **return_data)
{
    olibc_api_retval_t retval;
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

    retval = olibc_list_remove_node(list, element, 
            data, return_data);

    if (retval != OLIBC_RETVAL_SUCCESS)  {
        return (retval);
    }

    return OLIBC_RETVAL_SUCCESS;
}

olibc_api_retval_t
olibc_list_remove_node (olibc_list_t *list, 
                        olibc_list_element_t *element, 
                        void *data, void **return_data)
{
    if (!list || !element || !data) {
        return (OLIBC_RETVAL_INVALID_INPUT);
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
    free(element);

    return (OLIBC_RETVAL_SUCCESS);
}  

olibc_api_retval_t
olibc_list_get_head_elem (olibc_list_t *list, olibc_list_element_t **elem)
{

    if (!list || !elem) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    }

    *elem = NULL;
    if (!olibc_list_is_empty(list)) {
        *elem = list->head;
        return (OLIBC_RETVAL_SUCCESS);
    }
    return (OLIBC_RETVAL_EMPTY_DATA_SET);
}

olibc_api_retval_t
olibc_list_get_data (olibc_list_element_t *elem, 
                     void **return_data)
{
    if (!elem) {
        return (OLIBC_RETVAL_INVALID_INPUT);
    } 
    *return_data = elem->data;
    return (OLIBC_RETVAL_SUCCESS);
}

olibc_api_retval_t 
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
