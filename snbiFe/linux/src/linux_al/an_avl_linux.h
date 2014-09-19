/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_AVL_LINUX_H__
#define __AN_AVL_LINUX_H__

typedef struct linux_avl_node_t_ {
    struct linux_avl_node_t_ *left;
    struct linux_avl_node_t_ *right;
    void *data;
} linux_avl_node_t;

typedef struct linux_avl_tree_t_ {
    linux_avl_node_t *root;
    void * compare_func;
    unsigned int node_count;
} linux_avl_tree_t;

#endif
