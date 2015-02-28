
/*
 *  Sreekanth Maddali
 *
 * Library for maintainance of AVL Balanced Trees
 *
 *  Copyright (c) 2015 by cisco Systems, Inc.
 *  All rights reserved.
 */

#ifndef _AVL_H
#define _AVL_H 1

typedef struct node
{
  void *data;
  struct node *left,*right;
  int height;
}node_t;

typedef int (*avl_cmp_fn_f)(void *, void *);

typedef struct tree
{
  node_t *root;
  avl_cmp_fn_f compare_fun;
}tree_t;

int avl_init(tree_t *tree, avl_cmp_fn_f cmp_fn);
int avl_insert_node(tree_t *, void *);
int avl_delete_node(tree_t *, void *);
int avl_get_count(tree_t *tree);
void avl_print_tree(tree_t *);

#endif 

