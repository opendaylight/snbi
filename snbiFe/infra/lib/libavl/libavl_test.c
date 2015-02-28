
/*
 *  Sreekanth Maddali
 *
 * Library for maintainance of AVL Balanced Trees
 *
 *  Copyright (c) 2015 by cisco Systems, Inc.
 *  All rights reserved.
 */

#include<stdio.h>
#include"libavl.h"

int compare(void *val1, void *val2)
{
  return (int)(*(int *)val1 - *(int *)val2);
}

int main()
{
  node_t *root=NULL;
  tree_t T;
  int arr[20] = {1, 20, 10, 4, 9, 15, 40, 23, 5, 25, 11, 14, 3, 35, 30, 21, 2, 29, 39, 7};
  int i, rv;

  avl_init(&T, compare);

  printf("\n");
  for(i=0; i<20; i++)
  {
    rv = avl_insert_node(&T, &arr[i]);
    if(rv < 0)
    {
      printf("Unable to insert node, exiting\n");
    }
  }
  printf("Inserted 20 nodes, count is: %d, expected is: %d\n", avl_get_count(&T),20);
  avl_print_tree(&T);

  for(i=0; i<20; i=i+3)
  {
    rv = avl_delete_node(&T, &arr[i]);
    if(rv < 0)
    {
      printf("Unable to delete node, exiting\n");
    }
  }
  printf("Deleted 7 nodes, count is: %d, expected is: %d\n", avl_get_count(&T),13);
  avl_print_tree(&T);

  for(i=1; i<20; i=i+2)
  {
    rv = avl_delete_node(&T, &arr[i]);
    if(rv < 0)
    {
      printf("Unable to delete node, exiting\n");
    }
  }
  printf("Deleted 7 nodes, count is: %d, expected is: %d\n", avl_get_count(&T),6);
  avl_print_tree(&T);

  for(i=2; i<20; i=i+2)
  {
    rv = avl_delete_node(&T, &arr[i]);
    if(rv < 0)
    {
      printf("Unable to delete node, exiting\n");
    }
  }
  printf("Deleted 6 nodes, count is: %d, expected is: %d\n", avl_get_count(&T),0);

  return (0);
}

