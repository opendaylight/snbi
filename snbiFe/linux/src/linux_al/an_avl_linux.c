/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_types.h"
#include "an_logger.h"
#include "an_avl.h"
#include "an_avl_linux.h"

an_avl_node_t*
an_avl_get_first_node (an_avl_node_t *top_node, an_avl_tree *tree)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return NULL;
}

boolean 
an_avl_insert_node (an_avl_top_p *top_node, an_avl_node_t *node, an_avl_compare_f compare, an_avl_tree *tree) 
{
    void *val= NULL;

    if (!tree || !node) {
      return (FALSE);   
    }
    
    if (val == NULL) {
        return (FALSE);
    }
    return TRUE;
}

boolean 
an_avl_remove_node (an_avl_top_p *top_node, an_avl_node_t *node, an_avl_compare_f compare, an_avl_tree *tree)
{
    void *val= NULL;
    if (!tree || !node) {
      return (FALSE);   
    }
    if (val == NULL) {
        return (FALSE);
    }

    return TRUE;
}

an_avl_node_t* 
an_avl_search_node (an_avl_top_p top_node, an_avl_node_t *node, an_avl_compare_f compare, an_avl_tree *tree)
{
    void *node_found=NULL;
    if (!tree || !node) {
      return (FALSE);   
    }

    if (node_found == NULL) {
        return NULL; 
    }

    return node_found;
}

an_avl_node_t *
an_avl_get_next_node (an_avl_top_p top_node, an_avl_node_t *node, an_avl_compare_f compare, an_avl_tree *tree)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (NULL);
}

boolean 
an_avl_walk_all_nodes (an_avl_top_p *top_node, an_avl_walk_f walk, an_avl_compare_f compare, void *args, an_avl_tree *tree)
{
  
    if (!tree->root) {
      return (FALSE);   
    }
    // avl_tree_walk_all_nodes return 0 for success
    return (!avl_tree_walk_all_nodes(tree, walk, args) ? TRUE : FALSE); 
}

an_cerrno 
an_avl_init (an_avl_tree *tree, an_avl_compare_f compare_func) {

    if (tree == NULL || compare_func == NULL) {
        return -1;
    } 

    return (avl_tree_init(tree, compare_func)); 
}

an_cerrno 
an_avl_uninit (an_avl_tree *tree) {
    return avl_tree_uninit(tree); 
}
