
/*
 *  Sreekanth Maddali
 *
 * Library for maintainance of AVL Balanced Trees
 *
 */

#include<stdio.h>
#include<stdlib.h>
#include"avl.h"

static int node_count;

/*******************
 * Local Functions *
 *******************/
static int get_height (avl *node)
{
    int lh, rh;

    if(node==NULL)
        return(0);

    if(node->left==NULL)
        lh = 0;
    else
        lh = node->left->height + 1;

    if(node->right==NULL)
        rh = 0;
    else
        rh = node->right->height + 1;

    return((lh>rh) ? lh : rh);
}

static int bal_factor (avl *node)
{
    int lh, rh;

    if(node==NULL)
        return(0);

    if(node->left==NULL)
        lh = 0;
    else
        lh = node->left->height + 1;

    if(node->right==NULL)
        rh = 0;
    else
        rh = node->right->height + 1;

    return(lh - rh);
}

static avl * rotate_right (avl *nodeA)
{
    avl *nodeB;

    nodeB         = nodeA->left;
    nodeA->left   = nodeB->right;
    nodeB->right  = nodeA;
    nodeA->height = get_height(nodeA);
    nodeB->height = get_height(nodeB);

    return(nodeB);
}

static avl * rotate_left (avl *nodeA)
{
    avl *nodeB;

    nodeB         = nodeA->right;
    nodeA->right  = nodeB->left;
    nodeB->left   = nodeA;
    nodeA->height = get_height(nodeA);
    nodeB->height = get_height(nodeB);

    return(nodeB);
}

static avl *do_insert (avl *node, avl_compare_cb_f cmp_fn, void *new)
{
    if(node==NULL)
    {
        return(new);
    }

    if(cmp_fn(new, node) == AVL_COMPARE_GT)
    {
        node->right = do_insert(node->right, cmp_fn, new);

        if(bal_factor(node)==-2)
        {
            if(cmp_fn(new, node->right) == AVL_COMPARE_GT)
            {
                node = rotate_left(node);
            }
            else
            {
                node->right = rotate_right(node->right);
                node = rotate_left(node);
            }
        }
    }
    else if(cmp_fn(new, node) == AVL_COMPARE_LT)
    {
        node->left = do_insert(node->left, cmp_fn, new);

        if(bal_factor(node)==2)
        {
            if(cmp_fn(new, node->left) == AVL_COMPARE_LT)
            {
                node = rotate_right(node);
            }
            else
            {
                node->left = rotate_left(node->left);
                node = rotate_right(node);
            }
        }
    }

    node->height = get_height(node);

    return(node);
}

static void reset_node_count (void)
{
    node_count = 0;
}

static int get_count (avl *node)
{
    if(node!=NULL)
    {
        ++node_count;
        get_count(node->left);
        get_count(node->right);
    }
    return(node_count);
}

avl *remove_node (avl *node)
{
    avl *temp1;
    avl *temp = node;
    if(node->right == NULL)
    {
        if(node->left)
            node->left->height = get_height(node->left);
        return node->left;
    } else {
        //traverse
        if(node->right->left == NULL)
        {
            node->right->left = temp->left;
            node->right->height = get_height(node->right);
            return node->right;
        } else {
            node = node->right;
            while(node->left->left)
                node = node->left;
            if(node->left->right == NULL)
            {
                node->left->left = temp->left;
                node->left->right = temp->right;
                temp = node->left;
                node->left = NULL;
                node->height = get_height(node);
                temp->height = get_height(temp);
                return temp;
            } else {
                temp1 = node->left;
                node->left = remove_node(node->left);
                temp1->left = temp->left;
                temp1->right = temp->right;
                node = temp1;
                //Check for balance of tree and rebalance
                if(bal_factor(node)==-2)
                {
                    if(bal_factor(node->right)<=0)
                    {
                        node = rotate_left(node);
                    }
                    else
                    {
                        node->right = rotate_right(node->right);
                        node = rotate_left(node);
                    }
                }

                return node;
            }
        }
    }
}

static avl *do_remove (avl *node, avl_compare_cb_f cmp_fn, avl *del_node)
{
    if(!node || !cmp_fn || !del_node)
    {
        return(NULL);
    }
    else
    {
        if(cmp_fn(del_node, node) == AVL_COMPARE_GT)
        {
            node->right = do_remove(node->right, cmp_fn, del_node);

            if(bal_factor(node)==2)
            {
                if(bal_factor(node->left)>=0)
                {
                    node = rotate_right(node);
                }
                else
                {
                    node->left = rotate_left(node->left);
                    node = rotate_right(node);
                }
            }
            node->height = get_height(node);
        }
        else
        {
            if(cmp_fn(del_node, node) == AVL_COMPARE_LT)
            {
                node->left = do_remove(node->left, cmp_fn, del_node);

                /* Check for balance of tree and rebalance */
                if(bal_factor(node)==-2)
                {
                    if(bal_factor(node->right)<=0)
                    {
                        node = rotate_left(node);
                    }
                    else
                    {
                        node->right = rotate_right(node->right);
                        node = rotate_left(node);
                    }
                }
                node->height = get_height(node);
            }
            else
            {
                /* node to be deleted is found */
                node = remove_node(node);

            }
        }
    }

    return(node);
}

int do_walk (avl *node, avl_walk_cb_f walk_cb, void *args)
{
    if (node == NULL) {
        return 0;
    }

    if (node->right) {
        if (!do_walk(node->right, walk_cb, args)) {
            return 0;
        }
    }

    if (!walk_cb(node, args)) {
        return 0;
    }

    if (node->left) {
        if (!do_walk(node->left, walk_cb, args)) {
            return 0;
        }
    }
    return 1;
}

int do_search (avl *node, avl *search_node, avl_compare_cb_f cmp_fn,
               avl **found_node)
{
    avl_compare_e diff;

    if (!node) {
        return 0;
    }

    diff = cmp_fn(search_node, node);

    if (diff == AVL_COMPARE_LT) { 
        return(do_search(node->left, search_node, cmp_fn, found_node));
    } else if (diff == AVL_COMPARE_GT) {
        return(do_search(node->right, search_node, cmp_fn, found_node));
    } else {
        *found_node = node;
        return 1;
    }
}

/********************
 * Public Functions *
 ********************/
int avl_tree_init (avl_tree *tree, avl_compare_cb_f cmp_fn)
{
    if(!tree  || !cmp_fn)
        return(-1);

    tree->root = NULL;
    tree->compare_fun = cmp_fn;
    return(0);
}

int avl_insert (avl_tree *tree, void *new)
{
    if(!tree || !tree->compare_fun)
        return(-1);

    tree->root = do_insert(tree->root, tree->compare_fun, new);
    return(0);
}

int avl_remove (avl_tree *tree, void *del_node)
{
    if(!tree || !tree->compare_fun)
        return(-1);

    tree->root = do_remove(tree->root, tree->compare_fun, del_node);
    return(0);
}

int avl_tree_uninit (avl_tree *tree) {
    if (!tree || tree->root) {
        //The tree is not empty.
        return (-1);
    }

    tree->compare_fun = NULL;
    return 0;
}

int avl_get_count (avl_tree *tree)
{
    if(!tree || !tree->compare_fun)
        return(-1);

    reset_node_count();
    return (get_count(tree->root));
}

/* function 'avl_tree_walk_all_nodes'
 * returning 0 for failure and 1 for success, unlike all other functions
 * which are written to return 0 in success case and -1 in failure case
 * This is done make sure that this library is compatible to 
 * already existing application using this.
 */
int avl_tree_walk_all_nodes (avl_tree *tree, avl_walk_cb_f walk_fn,
        void *args)
{
    return (do_walk(tree->root, walk_fn, args));
}

/* function 'avl_get_first_node'
 * returning 0 for failure and 1 for success, unlike all other functions
 * which are written to return 0 in success case and -1 in failure case
 * This is done make sure that this library is compatible to 
 * already existing application using this.
 */
int avl_get_first_node (avl_tree *tree, avl **node)
{
    if (!tree || !node) {
        return 0;
    }

    *node = tree->root;
    return 1;
}

/* function 'avl_search'
 * returning 0 for failure and 1 for success, unlike all other functions
 * which are written to return 0 in success case and -1 in failure case
 * This is done make sure that this library is compatible to 
 * already existing application using this.
 */
avl* avl_search (avl_tree* tree, avl* node)
{
    avl *found_node = NULL;
    if (!tree || !tree->root || !tree->compare_fun) {
        return NULL;
    }
    if (do_search(tree->root, node, tree->compare_fun, &found_node)) {
        return found_node;
    }
    return NULL;
}

