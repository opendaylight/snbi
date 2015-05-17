
/*
 *  Sreekanth Maddali
 *
 * Library for maintainance of AVL Balanced Trees
 *
 */

#ifndef _AVL_H
#define _AVL_H 1

struct node
{
  struct node *left,*right;
  int height;
};
typedef struct node avl;

typedef enum avl_compare_e {
    AVL_COMPARE_LT,
    AVL_COMPARE_EQ,
    AVL_COMPARE_GT
} avl_compare_e;

typedef avl_compare_e (*avl_compare_cb_f)(const avl *, const avl *);

typedef int (*avl_walk_cb_f) (avl *node, void *args);

struct tree {
  avl *root;
  avl_compare_cb_f compare_fun;
};

typedef struct tree avl_tree;

int avl_tree_init(avl_tree *tree, avl_compare_cb_f cmp_fn);

int avl_insert(avl_tree *, void *);

int avl_get_count(avl_tree *tree);

void avl_print_tree(avl_tree *);

int avl_remove(avl_tree *tree, void *del_node);

int avl_tree_uninit(avl_tree *tree);

/* function 'avl_tree_walk_all_nodes'
 * returning 0 for failure and 1 for success, unlike all other functions
 * which are written to return 0 in success case and -1 in failure case
 * This is done make sure that this library is compatible to 
 * already existing application using this.
 */
int avl_tree_walk_all_nodes(avl_tree *tree, avl_walk_cb_f walk_fn, void *args);

/* function 'avl_get_first_node'
 * returning 0 for failure and 1 for success, unlike all other functions
 * which are written to return 0 in success case and -1 in failure case
 * This is done make sure that this library is compatible to 
 * already existing application using this.
 */
int avl_get_first_node(avl_tree *t, avl **node);

/* function 'avl_search'
 * returning 0 for failure and 1 for success, unlike all other functions
 * which are written to return 0 in success case and -1 in failure case
 * This is done make sure that this library is compatible to 
 * already existing application using this.
 */
avl* avl_search(avl_tree* tree, avl* node);

#endif 

