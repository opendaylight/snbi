/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_list.h>
#include <an_logger.h>

an_cerrno 
an_list_create (an_list_t **list, 
                           const char *list_name)
{
    an_list_t *new_list = NULL;
    new_list = (an_list_t *)malloc(sizeof(an_list_t));
    if (!new_list) {
        return AN_CERR_FAIL;
    }
    an_memset(new_list, 0, sizeof(an_list_t));
    new_list->count   = 0;
    new_list->head    = NULL;
    new_list->tail    = NULL;
    new_list->maximum = 0;
    new_list->name = list_name;
    *list = new_list;
    return AN_CERR_SUCCESS;
}

an_cerrno 
an_list_destroy (an_list_t **list)
{
    if (!list || !(*list)) {
        return 0;
    } 

    while (!an_list_is_empty(*list)) {
        an_list_dequeue_node(*list);
    }
    an_free(*list);
    *list = NULL;
    return AN_CERR_SUCCESS;
}

boolean 
an_list_is_valid (an_list_t *list)
{
    return (list ? TRUE : FALSE);
}

boolean 
an_list_is_empty (an_list_t *list)
{   
    return (list->head ? FALSE : TRUE);
}

void* an_list_lookup_node (an_list_t *list, an_list_element_t *elem,
                      void* data, an_list_comp_handler comp_handler)
{
   void *runner = NULL;
   an_list_element_t *element = NULL;
   int ret;
    
   if (!list || !comp_handler || !data) {
       return NULL;
   }
   
   AN_FOR_ALL_DATA_IN_LIST(list, element, runner) {
       ret = comp_handler(runner, data);
       if (ret == 0) {
           /* Match found */    
           return data;
       }
   }

   return (NULL);
}

/* Insert first element at the HEAD of the list.
 * All subsequent elements to be added at the TAIL
 * of the list.
 */
void
an_list_enqueue_node (an_list_t *list, void  *data) 
{
    an_list_element_t *new_element = NULL;
    an_list_element_t *current = NULL;
    
    if ((list == NULL) || (data == NULL)) {
        return;
    }
    
    if (!an_list_is_valid(list)) {
        return;
    }
        
    new_element = (an_list_element_t *)malloc(sizeof(an_list_element_t));
    if (!new_element) {
        return;
    }

    new_element->data = data; 
    current = list->tail;

    if (!current) {
    /* Insert new element at the head of the list */
        new_element->next = list->head;
        list->head = new_element;
        new_element->prev = NULL; 
    }
    else {
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
    return;
}

void*
an_list_dequeue_node (an_list_t *list)
{
   an_list_element_t *element = NULL;
   void *data = NULL;

   if (list == NULL) {
       return NULL;
   }

   element = an_list_get_head_elem(list);    
   data = an_list_get_data(element);
   an_list_remove(list, element, data); 

   return (data);
}

void*
an_list_remove (an_list_t *list, an_list_element_t *element, void *data)
{
    if (!list || !element || !data) {
        return NULL;
    }

    if ((element->list != list) || (element->data != data)) {
        return NULL;
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

    element->list->count--;
    element->next = element->prev = NULL;
    element->list = NULL;
    an_free(element);

    return (data);
}  

an_list_element_t*
an_list_get_head_elem (an_list_t *list)
{
    if (!an_list_is_empty(list)) {
        return ((an_list_element_t *)list->head);
    }
    return (NULL);
}

void*
an_list_get_data (an_list_element_t *elem)
{
    return (elem ? elem->data : NULL);     
}

an_cerrno 
an_list_walk (an_list_t *list, an_list_walk_handler func,
                     void *context)
{   
    an_list_element_t *runner = NULL, *next = NULL;
    int ret_val = 0;
    if (!an_list_is_valid(list) || !func) {
        return 0;
    }     
    AN_FOR_ALL_ELEMENTS_IN_LIST_SAVE_NEXT(list, runner, next) {
        ret_val = (*func)(list, runner, next, context);
        if(ret_val) {
           // The user returned some non-zero value, break and return
           break;
        } 
    }
    return 0;
}

