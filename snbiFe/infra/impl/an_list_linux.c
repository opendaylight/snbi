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
#include <olibc_list.h>
#include <an_olibc.h>

an_cerrno 
an_list_create (an_list_t **list, 
                const char *list_name)
{
    return (an_map_olibc_retval(olibc_list_create(list, list_name)));
}

an_cerrno 
an_list_destroy (an_list_t **list)
{
    return(an_map_olibc_retval(olibc_list_destroy(list, NULL)));
}

boolean 
an_list_is_valid (an_list_t *list)
{
    boolean is_valid = FALSE;
    if (CERR_IS_OK(an_map_olibc_retval(olibc_list_is_valid(list, &is_valid))) &&
            is_valid) {
        return TRUE;
    }
    return FALSE;
}

boolean 
an_list_is_empty (an_list_t *list)
{   
    boolean is_empty = TRUE;
    if (CERR_IS_OK(an_map_olibc_retval(olibc_list_is_empty(list, &is_empty)))) {
        return is_empty;
    }
    return  TRUE;
}

void* an_list_lookup_node (an_list_t *list, an_list_element_t *elem,
                          void* data, an_list_comp_handler comp_handler)
{
    void *return_data = NULL;
    if (CERR_IS_OK(an_map_olibc_retval(
                   olibc_list_lookup_node(list, data, comp_handler, 
                                          &return_data)))) {
        return return_data;
    }
    return NULL;
}

/* Insert first element at the HEAD of the list.
 * All subsequent elements to be added at the TAIL
 * of the list.
 */
void
an_list_enqueue_node (an_list_t *list, void  *data) 
{
    olibc_list_insert_node(list, NULL, data);
}

void*
an_list_dequeue_node (an_list_t *list)
{
    void *return_data = NULL;
    if (CERR_IS_OK(an_map_olibc_retval(olibc_list_dequeue_node(list,
                        &return_data)))) {
        return return_data;
    }
    return NULL;
}

void*
an_list_remove (an_list_t *list, an_list_element_t *element, void *data)
{
    void *return_data;

    if (CERR_IS_OK(an_map_olibc_retval(olibc_list_remove_node(list,
                                       data, NULL, &return_data)))) {
        return (return_data);
    }
    return NULL;
}  

an_list_element_t*
an_list_get_head_elem (an_list_t *list)
{
    olibc_list_element_t *elem = NULL;

    if (CERR_IS_OK(an_map_olibc_retval(olibc_list_get_head_elem(list, &elem)))) {
        return elem;
    }
    return NULL;
}

void*
an_list_get_data (an_list_element_t *elem)
{
    void *return_data = NULL;
    if (CERR_IS_OK(an_map_olibc_retval(olibc_list_get_data(elem,
                        &return_data)))) {
        return return_data;
    }
    return NULL;
}

an_cerrno 
an_list_walk (an_list_t *list, an_list_walk_handler func,
                     void *context)
{  
    return (an_map_olibc_retval(olibc_list_walk(list, 
                    (olibc_list_walk_handler)func, context)));
}

