/*
 * AN test cli for testing stubs.
 *
 *  Vijay Anand R
 *
 *  Copyright (c) 2010-2012, 2014 by cisco Systems, Inc.
 *  All rights reserved.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include "libcli.h"
#include <unistd.h>
#include "conf_an.h"
#include "show_an.h"
#include "an_types.h"
#include "an_mem.h"

#define MAX_RAND_ARRAY 10

an_avl_tree an_avl_test_tree;
static int node_index = 0;

typedef struct an_avl_test_node_t_ {
    an_avl_node_t avl_node;
    int data;
} an_avl_test_node_t;

static an_avl_test_node_t *node_store[MAX_RAND_ARRAY];

static  an_walk_e
an_avl_test_nodes_walk_func (an_avl_node_t *node, void *args) 
{
    an_avl_test_node_t *test_node = (an_avl_test_node_t *)node;

    if (node) {
        printf("\nAVL walking nodes :\n");
        printf("\tData : %d", test_node->data);
        if (args) {
            printf("\tArgs : %s\n", (char *) args);
        }
        return (AN_WALK_SUCCESS);
    }

    return (AN_WALK_FAIL);
}

static an_avl_compare_e
an_avl_test_compare_func (an_avl_node_t *nodeA, an_avl_node_t *nodeB)
{
    an_avl_test_node_t *test_nodeA = (an_avl_test_node_t *) nodeA;
    an_avl_test_node_t *test_nodeB = (an_avl_test_node_t *) nodeB; 

    if (!test_nodeA && !test_nodeB) {
        return (AN_AVL_COMPARE_EQ);
    } else if (!test_nodeA) {
        return (AN_AVL_COMPARE_LT);
    } else if (!test_nodeB) {
        return (AN_AVL_COMPARE_GT);
    }

    if (test_nodeA->data < test_nodeB->data) {
        return (AN_AVL_COMPARE_LT);
    } else if (test_nodeA->data > test_nodeB->data) {
        return (AN_AVL_COMPARE_GT);
    } else {
        return (AN_AVL_COMPARE_EQ);
    }
}


void an_test_init_tree (bool negation, int argc, char *argv[]) 
{
    printf("\nInside test init");
    an_memset(&an_avl_test_tree, 0, sizeof(an_avl_tree));
    an_avl_init(&an_avl_test_tree, an_avl_test_compare_func);
}

void an_test_insert_data (bool negation, int argc, char *argv[]) 
{
    if (node_index >= MAX_RAND_ARRAY) {
        return;
    }
    an_avl_test_node_t *test_node = an_malloc(sizeof(an_avl_test_node_t), 
                                             "AN AVL test node");
    if (!test_node) {
        printf("\n Failed to allocate test node");
        return;
    }

    an_memset(test_node, 0, sizeof(an_avl_test_node_t));

//    test_node->data = ++data_gen;
    test_node->data = rand();
    printf("\nInside test insert data %d", test_node->data);
    node_store[node_index++] = test_node;

    an_avl_insert_node(NULL, (an_avl_node_t *)test_node, 
                       an_avl_test_compare_func,
                       &an_avl_test_tree);
}


void an_test_walk_tree (bool negation, int argc, char *argv[]) 
{
    printf("\nInside test AVL tree");

    an_avl_walk_all_nodes(NULL, an_avl_test_nodes_walk_func,
                          an_avl_test_compare_func, 
                          "Tree walking ctxt string", 
                          &an_avl_test_tree);
}

void an_test_remove_data (bool negation, int argc, char *argv[]) 
{
    an_avl_test_node_t *test_node = NULL;
    if (node_index == 0) {
        return;
    }
    test_node =  node_store[--node_index];
    printf("\nInside test AVL remove data %d", test_node->data);
    an_avl_remove_node(NULL, (an_avl_node_t *)test_node, 
                       an_avl_test_compare_func, &an_avl_test_tree);
}

void an_test_get_first_node (bool negation, int argc, char *argv[]) 
{
    an_avl_test_node_t *test_node = NULL;
    test_node = (an_avl_test_node_t *)an_avl_get_first_node(NULL, 
                                                            &an_avl_test_tree);
    if (test_node) {
        printf("\nInside test AVL get first node %d", test_node->data); 
    }
}

void an_test_search_node (bool negation, int argc, char *argv[]) 
{
    an_avl_test_node_t *test_node = NULL;
    an_avl_test_node_t match_node = {0};

    match_node.data =  node_store[node_index-1]->data;
    test_node = (an_avl_test_node_t *)an_avl_search_node(NULL,
                                                (an_avl_node_t *) &match_node, 
                                                NULL, &an_avl_test_tree);

    if (test_node) {
        printf("\nInside avl search node found %d", test_node->data);
    }

}

void an_test_uninit_tree (bool negation, int argc, char *argv[]) 
{
}

void cli_an_test_init(cli_set_t *s) 
{

    cli_insert(s, "test avl-init ", "Init an AVL tree", 
            an_test_init_tree, false);
    cli_insert(s, "test avl-insert", "Insert an AVL tree", 
            an_test_insert_data, false);
    cli_insert(s, "test avl-walk", "Walk an AVL tree", 
            an_test_walk_tree, false);
    cli_insert(s, "test avl-remove", "delet from an avl tree", 
            an_test_remove_data, false);
    cli_insert(s, "test avl-search", 
            "search the node",
            an_test_search_node, false);
    cli_insert(s, "test avl-get-firstnode", 
            "Get the first node from an avl tree", 
            an_test_get_first_node, false);
    cli_insert(s, "test avl-uninit", "uninint an avl tree", 
            an_test_uninit_tree, false);
}

