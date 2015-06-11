/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_logger.h>
#include <an_avl.h>
#include <an_avl_linux.h>

an_avl_node_t*
an_avl_get_first_node (an_avl_node_t *top_node, an_avl_tree *tree)
{
    an_avl_node_t *first_node = NULL;
    olibc_avl_get_first_node(tree, &first_node);
    return (first_node);
}

boolean 
an_avl_insert_node (an_avl_top_p *top_node, an_avl_node_t *node, an_avl_compare_f compare, an_avl_tree *tree) 
{
    if (!tree || !node) {
      return (FALSE);   
    }
    if (!olibc_avl_insert(tree, node)) {
        return TRUE;
    }
    return FALSE;
}

boolean 
an_avl_remove_node (an_avl_top_p *top_node, an_avl_node_t *node, an_avl_compare_f compare, an_avl_tree *tree)
{
    if (!tree || !node) {
      return (FALSE);   
    }
    if (!olibc_avl_remove(tree, node)) {
        return TRUE;
    }
    return FALSE;
}

an_avl_node_t* 
an_avl_search_node (an_avl_top_p top_node, an_avl_node_t *node, an_avl_compare_f compare, an_avl_tree *tree)
{
    if (!tree || !node) {
      return (FALSE);   
    }
    return (olibc_avl_search(tree, node));
}

an_avl_node_t *
an_avl_get_next_node (an_avl_top_p top_node, an_avl_node_t *node, an_avl_compare_f compare, an_avl_tree *tree)
{
printf("\n[SNBI_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (NULL);
}

boolean 
an_avl_walk_all_nodes (an_avl_top_p *top_node, an_avl_walk_f walk, an_avl_compare_f compare, void *args, an_avl_tree *tree)
{
  
    if (!tree->root) {
      return (FALSE);   
    }
    // avl_tree_walk_all_nodes return 0 for success
    return (olibc_avl_tree_walk_all_nodes(tree, (olibc_avl_walk_cb_f)walk, args));
}

an_cerrno 
an_avl_init (an_avl_tree *tree, an_avl_compare_f compare_func) {

    if (tree == NULL || compare_func == NULL) {
        return -1;
    } 
    return (olibc_avl_tree_init(tree, (olibc_avl_compare_cb_f)compare_func));
}

an_cerrno 
an_avl_uninit (an_avl_tree *tree) {
    return olibc_avl_tree_uninit(tree); 
}
