
/*
 *  Sreekanth Maddali
 *
 * Test code to test AVL library
 *
 */

#include<stdio.h>
#include<stdlib.h>
#include"../inc/olibc_avl.h"

struct test_avl_node{
    olibc_avl avl_node;
    void *data;
};

typedef struct test_avl_node test_avl_node_t;

static int walk_sum = 0;

int compare(void *val1, void *val2)
{
    return (int)(*(int *)val1 - *(int *)val2);
}

/*
 *My compare function 
 */
static olibc_avl_compare_e
my_compare_func (const olibc_avl *nodeA, const olibc_avl *nodeB)
{
    int valA, valB;
    test_avl_node_t *test_nodeA = (test_avl_node_t *) nodeA;
    test_avl_node_t *test_nodeB = (test_avl_node_t *) nodeB;

    if (!test_nodeA && !test_nodeB) {
        return (OLIBC_AVL_COMPARE_EQ);
    } else if (!test_nodeA) {
        return (OLIBC_AVL_COMPARE_LT);
    } else if (!test_nodeB) {
        return (OLIBC_AVL_COMPARE_GT);
    }

    valA = *(int *)test_nodeA->data;
    valB = *(int *)test_nodeB->data;

    if (valA < valB) {
        return (OLIBC_AVL_COMPARE_LT);
    } else if (valA > valB) {
        return (OLIBC_AVL_COMPARE_GT);
    } else {
        return (OLIBC_AVL_COMPARE_EQ);
    }
}

/*
 *My walk function here adds up the numbers in the tree and
 *the value passed in arg at every node into walk_sum.
 */
int my_walk_func (olibc_avl *node, void *arg)
{
    test_avl_node_t *test_node = (test_avl_node_t *) node;
    walk_sum = walk_sum + *(int *)test_node->data + *(int *)arg;
}

/*
 *Just copied the get height and balance_factor functions 
 * here as its not needed to be exposed through our library.
 */
static int get_height (olibc_avl *node)
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

static int bal_factor (olibc_avl *node)
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

static void print_preorder (olibc_avl *node)
{
    test_avl_node_t *test_node = (test_avl_node_t *)node;
    if(node!=NULL)
    {
        printf("%d(%d/%d) ", *(int *)test_node->data, bal_factor(node), get_height(node));
        print_preorder(node->left);
        print_preorder(node->right);
    }
}

static void print_inorder (olibc_avl *node)
{
    test_avl_node_t *test_node = (test_avl_node_t *)node;
    if(node!=NULL)
    {
        print_inorder(node->left);
        printf("%d(%d/%d) ", *(int *)test_node->data, bal_factor(node), get_height(node));
        print_inorder(node->right);
    }
}

static void print_postorder (olibc_avl *node)
{
    test_avl_node_t *test_node = (test_avl_node_t *)node;
    if(node!=NULL)
    {
        print_postorder(node->left);
        print_postorder(node->right);
        printf("%d(%d/%d) ", *(int *)test_node->data, bal_factor(node), get_height(node));
    }
}

void avl_print_tree (olibc_avl_tree *tree)
{
    if(!tree)
        return;

    printf("\nInorder sequence:\n");
    print_inorder((olibc_avl *)tree->root);
    printf("\n");

    printf("\nPreorder sequence:\n");
    print_preorder((olibc_avl *)tree->root);
    printf("\n");

    printf("\nPostorder sequence:\n");
    print_postorder((olibc_avl *)tree->root);
    printf("\n");
}

int main ()
{
    test_avl_node_t *node, N;
    olibc_avl_tree T;
    int arr[20] = {11,20,40,4,9,15,10,23,5,25,1,14,3,35,30,21,2,29,39,7}; 
    test_avl_node_t *ptrs[20] = {}; 
    int i, rv, val;
    int diff = 2;

    ///////////////////////
    //TC-1: Initialise tree
    ///////////////////////
    rv = olibc_avl_tree_init(&T, my_compare_func);
    if(rv==0)
    {
        printf("====== TC-1: Initialise tree: SUCCESS \n");
    } else {
        printf("====== TC-1: Initialise tree: FAIL \n");
    }

    ////////////////////////////////
    //TC-2: Insert elements randomly
    ////////////////////////////////
    for(i=0; i<20; i++)
    {
        ptrs[i] = malloc(sizeof(test_avl_node_t));
        if(ptrs[i]==NULL)
        {
            printf("Unable to allocate a node");
            exit(0);
        }
        ptrs[i]->data = (void *)&arr[i];
        rv = olibc_avl_insert(&T, (void *)ptrs[i]);
        if(rv < 0)
        {
            printf("Unable to insert node, exiting\n");
        }
    }
    if(olibc_avl_get_count(&T) == 20)
    {
        printf("====== TC-2: Insert elements randomly: SUCCESS \n");
    } else {
        printf("====== TC-2: Insert elements randomly: FAIL \n");
        printf("Inserted 20 nodes, count is: %d, expected is: %d\n",
               olibc_avl_get_count(&T),20);
        avl_print_tree(&T);
    }

    /////////////////////////////////////////////////
    //TC-3: Get first node from Tree without elements
    /////////////////////////////////////////////////
    node = &N;
    rv = olibc_avl_get_first_node (&T, (olibc_avl **)&node);
    val = *(int *)node->data;
    if((rv==1) && (val == 11))
    {
        printf("====== TC-3: Get first node from Tree without elements: SUCCESS \n");
    } else {
        printf("====== TC-3: Get first node from Tree without elements: FAIL \n");
        printf("rv:%d, first node data:%d\n", rv, *(int *)node->data);
    }

    //////////////////////////////////////
    //TC-4: Uninit Tree with some elements
    //////////////////////////////////////
    rv = olibc_avl_tree_uninit(&T);
    if(rv==-1)
    {
        printf("====== TC-4: Uninit Tree with some elements: SUCCESS \n");
    } else {
        printf("====== TC-4: Uninit Tree with some elements: FAIL \n");
    }

    /////////////////////////////////////
    //TC-5: Delete some elements randomly
    /////////////////////////////////////
    for(i=0; i<20; i=i+3)
    {
        rv = olibc_avl_remove(&T, ptrs[i]);
        if(rv < 0)
        {
            printf("Unable to delete node, exiting\n");
        }
    }

    if(olibc_avl_get_count(&T) == 13)
    {
        printf("====== TC-5: Delete some elements randomly: SUCCESS \n");
    } else {
        printf("====== TC-5: Delete some elements randomly: FAIL \n");
        printf("Deleted 7 nodes, count is: %d, expected is: %d\n",
               olibc_avl_get_count(&T),13);

        avl_print_tree(&T);
    }

    /////////////////////////////////////////////////
    //TC-6: Get first node from Tree without elements
    /////////////////////////////////////////////////
    node = &N;
    rv = olibc_avl_get_first_node (&T, (olibc_avl **)&node);
    if(node)
        val = *(int *)node->data;
    if((rv) && (val == 14))
    {
        printf("====== TC-6: Get first node from Tree without elements: SUCCESS \n");
    } else {
        printf("====== TC-6: Get first node from Tree without elements: FAIL \n");
        printf("rv:%d, first node data:%d\n", rv, *(int *)node->data);
    }

    /////////////////////////////////////
    //TC-7: Search for exisiting element
    /////////////////////////////////////
    if(olibc_avl_search(&T, (olibc_avl *)ptrs[8]))
    {
        if(*(int *)node->data == *(int *)ptrs[8]->data)
            printf("====== TC-7: Search for exisiting element: SUCCESS \n");
    } else {
        printf("====== TC-7: Search for exisiting element: FAIL \n");
    }

    //////////////////////////////////////////
    //TC-8: Delete some more elements randomly
    //////////////////////////////////////////
    for(i=2; i<20; i=i+2)
    {
        rv = olibc_avl_remove(&T, ptrs[i]);
        if(rv < 0)
        {
            printf("Unable to delete node, exiting\n");
        }
    }

    if(olibc_avl_get_count(&T) == 7)
    {
        printf("====== TC-8: Delete some more elements randomly: SUCCESS \n");
    } else {
        printf("====== TC-8: Delete some more elements randomly: FAIL \n");
        printf("Deleted 6 nodes, count is: %d, expected is: %d\n", 
               olibc_avl_get_count(&T),7);
        avl_print_tree(&T);
    }

    /////////////////////////////////////////////////
    //TC-9: Get first node from Tree without elements
    /////////////////////////////////////////////////
    node = &N;
    rv = olibc_avl_get_first_node (&T, (olibc_avl **)&node);
    if(node)
        val = *(int *)node->data;
    if((rv) && (val == 20))
    {
        printf("====== TC-9: Get first node from Tree without elements: SUCCESS \n");
    } else {
        printf("====== TC-9: Get first node from Tree without elements: FAIL \n");
        printf("rv:%d, first node data:%d\n", rv, *(int *)node->data);
    }

    /////////////////////////////////////
    //TC-10: Search for exisiting element
    /////////////////////////////////////
    if(olibc_avl_search (&T, (void *)ptrs[7]))
    {
        printf("====== TC-10: Search for exisiting element: SUCCESS \n");
    } else {
        printf("====== TC-10: Search for exisiting element: FAIL \n");
    }

    ///////////////////////
    //TC-11: Walk all nodes
    ///////////////////////
    olibc_avl_tree_walk_all_nodes(&T, my_walk_func, (void *)&diff);
    if(walk_sum == 157)
    {
        printf("====== TC-11: Walk all nodes: SUCCESS \n");
    } else {
        printf("====== TC-11: Walk all nodes: FAIL \n");
    }

    ///////////////////////////////////////////
    //TC-12: Delete some more elements randomly
    ///////////////////////////////////////////
    for(i=1; i<20; i=i+2)
    {
        rv = olibc_avl_remove(&T, ptrs[i]);
        if(rv < 0)
        {
            printf("Unable to delete node, exiting\n");
        }
    }

    if(olibc_avl_get_count(&T) == 0)
    {
        printf("====== TC-12: Delete some more elements randomly: SUCCESS \n");
    } else {
        printf("====== TC-12: Delete some more elements randomly: FAIL \n");
        printf("Deleted 7 nodes, count is: %d, expected is: %d\n",
               olibc_avl_get_count(&T),0);
        avl_print_tree(&T);
    }

    /////////////////////////////////////////
    //TC-13: Search for non-exisiting element
    /////////////////////////////////////////
    if(olibc_avl_search (&T, (olibc_avl *)ptrs[7]))
    {
        printf("====== TC-13: Search for non-exisiting element: FAIL \n");
    } else {
        printf("====== TC-13: Search for non-exisiting element: SUCCESS \n");
    }

    //////////////////////////////////////
    //TC-14: Uninit Tree with some elements
    //////////////////////////////////////
    rv = olibc_avl_tree_uninit(&T);
    if(rv==0)
    {
        printf("====== TC-14: Uninit Tree without any elements: SUCCESS \n");
    } else {
        printf("====== TC-14: Uninit Tree without any elements: FAIL \n");
    }

    /////////////////////////////////////////////////
    //TC-15: Get first node from Tree without elements
    /////////////////////////////////////////////////
    node = &N;
    rv = olibc_avl_get_first_node (&T, (olibc_avl **)&node);
    if(rv)
    {
        printf("====== TC-15: Get first node from Tree without elements: SUCCESS \n");
    } else {
        printf("====== TC-15: Get first node from Tree without elements: FAIL \n");
        if(node)
            printf("rv:%d, first node data:%d\n", rv, *(int *)node->data);
    }

    return (0);
}



