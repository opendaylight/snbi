
/*
 *  Sreekanth Maddali
 *
 * Library for maintainance of AVL Balanced Trees
 *
 */

#ifndef _OLIBC_AVL_H
#define _OLIBC_AVL_H 1

struct node
{
  struct node *left,*right;
  int height;
};
typedef struct node olibc_avl;

typedef enum olibc_avl_compare_e {
    OLIBC_AVL_COMPARE_LT,
    OLIBC_AVL_COMPARE_EQ,
    OLIBC_AVL_COMPARE_GT
} olibc_avl_compare_e;

typedef olibc_avl_compare_e (*olibc_avl_compare_cb_f)(const olibc_avl *n1, 
                                                      const olibc_avl *n2);

typedef int (*olibc_avl_walk_cb_f) (olibc_avl *node, void *args);

struct tree
{
  olibc_avl *root;
  olibc_avl_compare_cb_f compare_fun;
};
typedef struct tree olibc_avl_tree;

int olibc_avl_tree_init(olibc_avl_tree *tree, olibc_avl_compare_cb_f cmp_fn);

int olibc_avl_insert(olibc_avl_tree *, void *);

int olibc_avl_get_count(olibc_avl_tree *tree);

void olibc_avl_print_tree(olibc_avl_tree *);

int olibc_avl_remove(olibc_avl_tree *tree, void *del_node);

int olibc_avl_tree_uninit(olibc_avl_tree *tree, olibc_avl_walk_cb_f walk_fn);

/* function 'olibc_avl_tree_walk_all_nodes'
 * returning 0 for failure and 1 for success, unlike all other functions
 * which are written to return 0 in success case and -1 in failure case
 * This is done make sure that this library is compatible to 
 * already existing application using this.
 */
int olibc_avl_tree_walk_all_nodes(olibc_avl_tree *tree, 
                                  olibc_avl_walk_cb_f walk_fn, 
                                  void *args);

/* function 'olibc_avl_get_first_node'
 * returning 0 for failure and 1 for success, unlike all other functions
 * which are written to return 0 in success case and -1 in failure case
 * This is done make sure that this library is compatible to 
 * already existing application using this.
 */
int olibc_avl_get_first_node(olibc_avl_tree *t, olibc_avl **node);

/* function 'olibc_avl_search'
 * returning 0 for failure and 1 for success, unlike all other functions
 * which are written to return 0 in success case and -1 in failure case
 * This is done make sure that this library is compatible to 
 * already existing application using this.
 */
olibc_avl* olibc_avl_search(olibc_avl_tree* tree, olibc_avl* node);

#endif 

