/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_types.h"
#include "an_list.h"
#include "an_logger.h"


an_cerrno 
an_list_create (an_list_t **list, 
                           const char *list_name)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return  (0);
}

an_cerrno 
an_list_destroy (an_list_t **list)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return  (0);
}

boolean 
an_list_is_valid (an_list_t *list)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}

boolean 
an_list_is_empty (an_list_t *list)
{   
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}

void* an_list_lookup_node (an_list_t *list, an_list_element_t *elem,
                      void* data, an_list_comp_handler comp_handler)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
   return (NULL);
}

void
an_list_enqueue_node (an_list_t *list, void  *data) 
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

void*
an_list_dequeue_node (an_list_t *list)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
   return (NULL);
}

void*
an_list_remove (an_list_t *list, an_list_element_t *element, void *data)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
   return (NULL);
}

an_list_element_t*
an_list_get_head_elem (an_list_t *list)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
   return (NULL);
}

void*
an_list_get_data (an_list_element_t *elem)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (NULL);
}

an_cerrno 
an_list_walk (an_list_t *list, an_list_walk_handler func,
                     void *context)
{   
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (0);
}

