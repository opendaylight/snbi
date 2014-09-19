/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_AVL_H__
#define __AN_AVL_H__

#include "an_types.h"

typedef enum an_avl_compare_e_ {
    AN_AVL_COMPARE_LT,
    AN_AVL_COMPARE_EQ,
    AN_AVL_COMPARE_GT,
} an_avl_compare_e;

typedef an_avl_compare_e (*an_avl_compare_f)(an_avl_node_t *node1, an_avl_node_t *node2);
typedef boolean (*an_avl_walk_f)(an_avl_node_t *node, void *args);

boolean an_avl_insert_node(an_avl_top_p *top_node, an_avl_node_t *node, 
                      an_avl_compare_f compare_func, an_avl_tree *tree);
boolean an_avl_remove_node(an_avl_top_p *top_node, an_avl_node_t *node, 
                      an_avl_compare_f compare_func, an_avl_tree *tree);
an_avl_node_t* an_avl_search_node(an_avl_top_p top_node, an_avl_node_t *node, 
                      an_avl_compare_f compare_func, an_avl_tree *tree);
an_avl_node_t* an_avl_get_next_node(an_avl_top_p top_node, an_avl_node_t *node, 
                      an_avl_compare_f compare_func, an_avl_tree *tree);
an_avl_node_t* an_avl_get_first_node(an_avl_node_t *top_node, 
                                     an_avl_tree *tree);
boolean an_avl_walk_all_nodes(an_avl_top_p *top_node, an_avl_walk_f walk_func, 
                      an_avl_compare_f compare_func, void *args, 
                      an_avl_tree *tree);
an_cerrno an_avl_init(an_avl_tree *tree, an_avl_compare_f compare_func);
an_cerrno an_avl_uninit(an_avl_tree *tree);

#endif
