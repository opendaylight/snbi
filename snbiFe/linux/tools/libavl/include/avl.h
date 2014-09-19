/*
 *  Vijay Anand R.
 *
 *  Copyright (c) 2014 by cisco Systems, Inc.
 *  All rights reserved.
 *
 */


/*
 * ANSI C Library for maintainance of AVL Balanced Trees
 *
 * ref.:
 *  G. M. Adelson-Velskij & E. M. Landis
 *  Doklady Akad. Nauk SSSR 146 (1962), 263-266
 *
 * see also:
 *  D. E. Knuth: The Art of Computer Programming Vol.3 (Sorting and Searching)
 *
 * (C) 2000 Daniel Nagy, Budapest University of Technology and Economics
 * Released under GNU General Public License (GPL) version 2
 *
 */

#ifndef _AVL_H
#define _AVL_H 1

#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>

/* Data structures */


/* One element of the AVL tree */
typedef struct avl
{
   struct avl* left;
   struct avl* right;
   signed char balance;
} avl;

typedef enum avl_compare_e {
    AVL_COMPARE_LT,
    AVL_COMPARE_EQ,
    AVL_COMPARE_GT
} avl_compare_e;

typedef int (*avl_compare_cb_f) (avl *a, avl *b);
typedef int (*avl_walk_cb_f) (avl *node, void *args);

/* An AVL tree */
typedef struct avl_tree
{
   avl* root;
   avl_compare_cb_f compar;
} avl_tree;


/* Public methods */

/**
 * Init a avl tree, memory of the tree should be allocated by the caller.
 * returns 0 if successfully inited the tree.
 * returns 1 if init of tree failed.
 */
int avl_tree_init(avl_tree *t, avl_compare_cb_f compar);

/**
  * Walk the entire tree and call walk_cb with node and args as input, 
  * the walk_cb can stop the tree walk at any point of time.
  * If all nodes in the tree were walked the API would return 0, 1 if not.
  */
bool avl_tree_walk_all_nodes(avl_tree *t, avl_walk_cb_f walk_cb, void *args);

/* Insert element a into the AVL tree t
 * returns 1 if the depth of the tree has grown
 * Warning: do not insert elements already present
 */
int avl_insert(avl_tree* t,avl* a);

/* Remove an element a from the AVL tree t
 * returns -1 if the depth of the tree has shrunk
 * Warning: if the element is not present in the tree, 
 *          returns 0 as if it had been removed succesfully.
 */
int avl_remove(avl_tree* t, avl* a);

/* Remove the root of the AVL tree t
 * Warning: dumps core if t is empty
 */
int avl_removeroot(avl_tree* t);

/* Iterate through elements in t from a range between a and b (inclusive)
 * for each element calls iter(a) until it returns 0
 * returns the last value returned by iterator or 0 if there were no calls
 * Warning: a<=b must hold
 */
int avl_range(avl_tree* t,avl* a,avl* b,int(*iter)(avl* a));

avl* avl_search(avl_tree* t, avl* a);
/*
 * Get the first node in the tree
 * returns FALSE if the tree is empty.
 */
bool avl_get_first_node (avl_tree *t, avl **node);

#endif /* avl.h */
