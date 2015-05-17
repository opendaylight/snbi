/*
 * AN test cli for testing stubs.
 *
 * Vijay Anand R
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <stdio.h>
#include <stdlib.h>
#include "an_types.h"
#include "an_mem.h"
#include <unistd.h>
#include <cparser.h>
#include <cparser_tree.h>


an_avl_tree an_avl_test_tree;

typedef struct an_avl_test_node_t_ {
    an_avl_node_t avl_node;
    uint32_t data;
} an_avl_test_node_t;

static  an_walk_e
an_avl_test_nodes_walk_func (an_avl_node_t *node, void *args) 
{
    an_avl_test_node_t *test_node = (an_avl_test_node_t *)node;

    if (node) {
        printf("AVL walking nodes :\n");
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

cparser_result_t 
cparser_cmd_test_avl_init (cparser_context_t *context)
{
    printf("Inside test init\n");
    an_memset(&an_avl_test_tree, 0, sizeof(an_avl_tree));
    an_avl_init(&an_avl_test_tree, an_avl_test_compare_func);
    return (CPARSER_OK);
}

cparser_result_t
cparser_cmd_test_avl_insert_value (cparser_context_t *context, 
                                   uint32_t *value_ptr)
{
    an_avl_test_node_t *test_node = an_malloc(sizeof(an_avl_test_node_t), 
                                             "AN AVL test node");
    if (!test_node) {
        printf("Failed to allocate test node\n");
        return (CPARSER_NOT_OK);
    }

    an_memset(test_node, 0, sizeof(an_avl_test_node_t));

    test_node->data = *value_ptr;
    printf("Inside test insert data %d\n", test_node->data);

    an_avl_insert_node(NULL, (an_avl_node_t *)test_node, 
                       an_avl_test_compare_func,
                       &an_avl_test_tree);
    return (CPARSER_OK);
}

cparser_result_t
cparser_cmd_test_avl_walk (cparser_context_t *context)
{
    printf("Inside test AVL tree\n");

    an_avl_walk_all_nodes(NULL, an_avl_test_nodes_walk_func,
                          an_avl_test_compare_func, 
                          "Tree walking ctxt string", 
                          &an_avl_test_tree);
    return (CPARSER_OK);
}

cparser_result_t
cparser_cmd_test_avl_remove_value (cparser_context_t *context,
                                   uint32_t *value_ptr)
{
    an_avl_test_node_t test_node;

    an_memset(&test_node, 0, sizeof(an_avl_test_node_t));
    test_node.data = *value_ptr;
    printf("Inside test AVL remove data %d\n", test_node.data);
    an_avl_remove_node(NULL, (an_avl_node_t *)&test_node, 
                       an_avl_test_compare_func, &an_avl_test_tree);
    return (CPARSER_OK);
}

cparser_result_t
cparser_cmd_test_avl_get_firstnode (cparser_context_t *context)
{
    an_avl_test_node_t *test_node = NULL;
    test_node = (an_avl_test_node_t *)an_avl_get_first_node(NULL, 
                                                            &an_avl_test_tree);
    if (test_node) {
        printf("Inside test AVL get first node %d\n", test_node->data); 
    }
    return (CPARSER_OK);
}

cparser_result_t 
cparser_cmd_test_avl_search_value  (cparser_context_t *context,
                                    uint32_t *value_ptr)
{
    an_avl_test_node_t *test_node = NULL;
    an_avl_test_node_t match_node;

    an_memset(&match_node, 0, sizeof(an_avl_test_node_t));
    match_node.data =  *value_ptr;
    test_node = (an_avl_test_node_t *)an_avl_search_node(NULL,
                                                (an_avl_node_t *) &match_node, 
                                                NULL, &an_avl_test_tree);

    if (test_node) {
        printf("Inside avl search node found %d\n", test_node->data);
    } else {
        printf("Failed to find the node\n");
    }
    return (CPARSER_OK);
}

cparser_result_t
cparser_cmd_test_avl_uninit (cparser_context_t *context)
{
    printf("Inside AVL uninit\n");
    return (CPARSER_OK);
}
