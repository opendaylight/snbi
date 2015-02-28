
/*
 *  Sreekanth Maddali
 *
 * Library for maintainance of AVL Balanced Trees
 *
 *  Copyright (c) 2015 by cisco Systems, Inc.
 *  All rights reserved.
 */

#include<stdio.h>
#include<stdlib.h>
#include"libavl.h"

static int *cntptr_to_reset;

static node_t *create_node()
{
  node_t *node;

  node = (node_t*) malloc(sizeof(node_t));
  if(node)
  {
    node->data = NULL;
    node->left = NULL;
    node->right = NULL;
  }

  return (node);
}

static int get_height(node_t *node)
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

static int bal_factor(node_t *node)
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

static node_t * rotate_right(node_t *nodeA)
{
  node_t *nodeB;

  nodeB         = nodeA->left;
  nodeA->left   = nodeB->right;
  nodeB->right  = nodeA;
  nodeA->height = get_height(nodeA);
  nodeB->height = get_height(nodeB);

  return(nodeB);
}

static node_t * rotate_left(node_t *nodeA)
{
  node_t *nodeB;

  nodeB         = nodeA->right;
  nodeA->right  = nodeB->left;
  nodeB->left   = nodeA;
  nodeA->height = get_height(nodeA);
  nodeB->height = get_height(nodeB);

  return(nodeB);
}

static node_t *do_insert(node_t *node, avl_cmp_fn_f cmp_fn, void *val)
{
  if(node==NULL)
  {
    node = create_node();

    if(node==NULL)
    {
      printf("Unable to create a new node\n");
      return(NULL);
    }
    node->data = val;
  }
  else
  {
    if(cmp_fn(val, node->data)>0)
    {
      node->right = do_insert(node->right, cmp_fn, val);

      if(bal_factor(node)==-2)
      {
        if(cmp_fn(val, node->right->data)>0)
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
    else
    {
      if(cmp_fn(val, node->data)<0)
      {
        node->left = do_insert(node->left, cmp_fn, val);

        if(bal_factor(node)==2)
        {
          if(cmp_fn(val, node->left->data)<0)
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
    }
  }

  node->height = get_height(node);

  return(node);
}

static node_t *do_delete(node_t *node, avl_cmp_fn_f cmp_fn, void *val)
{

  node_t *p;
  node_t *ret_node_t = NULL;

  if(node==NULL)
  {
    return(NULL);
  }
  else
  {
    if(cmp_fn(val, node->data)>0)
    {
      node->right = do_delete(node->right, cmp_fn, val);

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
    }
    else
    {
      if(cmp_fn(val, node->data)<0)
      {
        node->left = do_delete(node->left, cmp_fn, val);

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
      }
      else
      {
        //data to be deleted is found
        if(node->right !=NULL)
        {
          p = node->right;

          while(p->left != NULL)
            p = p->left;

          node->data = p->data;

          node->right = do_delete(node->right, cmp_fn, p->data);

          //Check for balance of tree and rebalance
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
        }
        else
        {
          ret_node_t = node->left;
          free(node);
          return(ret_node_t);
        }
      }
    }
  }

  node->height = get_height(node);

  return(node);
}

static void print_preorder(node_t *node)
{
  if(node!=NULL)
  {
    printf("%d(%d) ", *(int *)node->data, bal_factor(node));
    print_preorder(node->left);
    print_preorder(node->right);
  }
}

static void print_inorder(node_t *node)
{
  if(node!=NULL)
  {
    print_inorder(node->left);
    printf("%d(%d) ", *(int *)node->data, bal_factor(node));
    print_inorder(node->right);
  }
}

static void print_postorder(node_t *node)
{
  if(node!=NULL)
  {
    print_postorder(node->left);
    print_postorder(node->right);
    printf("%d(%d) ", *(int *)node->data, bal_factor(node));
  }
}

int avl_init(tree_t *tree, avl_cmp_fn_f cmp_fn)
{
  if(!tree)
    return(-1);

  tree->root = NULL;
  tree->compare_fun = cmp_fn;
  return(0);
}

int avl_insert_node(tree_t *tree, void *val)
{
  if(!tree || !tree->compare_fun)
    return(-1);

  tree->root = do_insert(tree->root, tree->compare_fun, val);
  return(0);
}

int avl_delete_node(tree_t *tree, void *val)
{
  if(!tree || !tree->compare_fun)
    return(-1);

  tree->root = do_delete(tree->root, tree->compare_fun, val);
  return(0);
}

static int get_count(node_t *node)
{
  static int count = 0;
  cntptr_to_reset = &count;

  if(node!=NULL)
  {
    ++count;
    get_count(node->left);
    get_count(node->right);
  }
  return(count);
}

int avl_get_count(tree_t *tree)
{

  int avl_node_count;
  node_t *node = tree->root;

  avl_node_count = get_count(node);
  *cntptr_to_reset = 0;
  return(avl_node_count);
}

void avl_print_tree(tree_t *tree)
{
  if(!tree)
    return;

  printf("\nInorder sequence:\n");
  print_inorder(tree->root);
  printf("\n");

  printf("\nPreorder sequence:\n");
  print_preorder(tree->root);
  printf("\n");

  printf("\nPostorder sequence:\n");
  print_postorder(tree->root);
  printf("\n");
}


