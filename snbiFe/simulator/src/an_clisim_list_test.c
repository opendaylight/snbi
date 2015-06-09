/**
  * Vijay Anand R <vanandr@cisco.com>
  *
  */
#include <an_list.h>
#include <stdio.h> 
#include <stdlib.h>
#include "an_types.h"
#include <cparser.h>
#include <cparser_tree.h>
#include <olibc_list.h>

an_list_t *test_list = NULL;

cparser_result_t
cparser_cmd_test_list_create (cparser_context_t *context)
{
    an_cerrno cerrno;

    cerrno = an_list_create(&test_list,
                            "AN list test");
    if (cerrno != AN_CERR_SUCCESS) {
        printf("Failed to create list \n");
        return CPARSER_NOT_OK;
    }

    printf("AN test list creation success \n");
    return (CPARSER_OK);
}

cparser_result_t
cparser_cmd_test_list_destroy(cparser_context_t *context)
{
    an_cerrno cerrno;

    cerrno = an_list_destroy(&test_list);
    if (cerrno != AN_CERR_SUCCESS) {
        printf("Failed to destroy list\n");
        return CPARSER_NOT_OK;
    }

    printf("Destroy of list success\n");
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_list_is_valid (cparser_context_t *context)
{
    boolean ret;
    ret = an_list_is_valid(test_list);

    printf("List is %s\n", ret ? "Valid":"Invalid");
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_list_is_empty (cparser_context_t *context)
{
    boolean ret;

    ret = an_list_is_empty(test_list);
    printf("List is %s\n", ret ? "Empty":"Not empty");
    return CPARSER_OK;
}

static 
int test_list_compare_func (void *data1, void *data2)
{
    uint32_t *udata1 = data1;
    uint32_t *udata2 = data2;

    if (udata1 && udata2 && *udata1 == *udata2) {
        return 0;
    }
    return 1;
}

cparser_result_t
cparser_cmd_test_list_lookup_node_value (cparser_context_t *context, 
                                         uint32_t *value_ptr)
{
    uint32_t *ret_data = NULL;

    ret_data = an_list_lookup_node(test_list, NULL, value_ptr,
                                   test_list_compare_func);

    if (ret_data) {
        printf("Data returned %u\n", *ret_data);
    } else {
        printf("Data returned is NULL\n");
    }

    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_list_enqueue_node_value (cparser_context_t *context,
                                          uint32_t *value_ptr)
{
    uint32_t *data = NULL;

    data = (uint32_t *)malloc(sizeof(uint32_t));

    if (!data) {
        printf("Failed to allocate memory for data \n");
        return CPARSER_NOT_OK;
    }
    *data = *value_ptr;
    an_list_enqueue_node(test_list, data);
    printf("Enqueued data %d\n", *data);
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_list_dequeue_node (cparser_context_t *context)
{
    uint32_t *ret_data = NULL;

    ret_data = an_list_dequeue_node(test_list);

    if (ret_data) {
        printf("Dequeue node returned %d\n", *ret_data);
    } else {
        printf("Dequeue node returned NULL\n");
    }
    return CPARSER_OK;
}

static
an_cerrno test_list_remove_walker_func (an_list_t  *list, 
                                  const an_list_element_t *current,
                                  an_list_element_t *next,
                                  void *context)
{
    uint32_t *elem_data = NULL;
    uint32_t *data = (uint32_t *)context;
    uint32_t *ret_data;

    if (!context || !list || !current || !next) {
        return 1;
    }

    elem_data = (uint32_t *)current->data;
    if (*data == *elem_data) {
        if ((ret_data = an_list_remove(list, 
                    (an_list_element_t *) current, elem_data))) {
            printf("Remove data %d \n",*ret_data);
            free(ret_data);
        } else {
            printf("Failed to delete data\n");
        }
        return 1;
    }
    return 0;
}

cparser_result_t
cparser_cmd_test_list_remove_node_value (cparser_context_t *context, 
                                         uint32_t *value_ptr)
{
    an_cerrno cerrno;
    cerrno = an_list_walk(test_list, test_list_remove_walker_func, value_ptr);

    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_test_list_get_head_data (cparser_context_t *context)
{
    an_list_element_t *head_elem = NULL;
    uint32_t *data;

    head_elem = an_list_get_head_elem(test_list);
    if (!head_elem) {
        printf("Null head element\n");
    } else {
        data = (uint32_t *)an_list_get_data(head_elem);
        printf("Head element returned %d\n", *data);
    }
    return CPARSER_OK;
}


an_cerrno 
test_list_print_walker_func (an_list_t *list, 
                             const an_list_element_t *current,
                             an_list_element_t *next,
                             void *context)
{
    uint32_t *elem_data = NULL;

    if (!list || !current) {
        return 1;
    }

    elem_data = (uint32_t *)current->data;

    printf("--->[%d]",*elem_data);
    return 0;
}

cparser_result_t
cparser_cmd_test_list_walk (cparser_context_t *context)
{
    an_cerrno cerrno;

    cerrno = an_list_walk(test_list, test_list_print_walker_func, NULL);
    printf("\n");
    return CPARSER_OK;
}

cparser_result_t 
cparser_cmd_test_list_iterator_walk (cparser_context_t *context)
{
    olibc_retval_t retval;
    uint32_t *return_data = NULL;
    olibc_list_iterator_hdl iter_hdl = NULL;

    retval = olibc_list_iterator_create(test_list, &iter_hdl);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to create iterator %s",
                olibc_retval_get_string(retval));
        return CPARSER_OK;
    }
    while (olibc_list_iterator_get_next(iter_hdl, (void **)&return_data) ==
        OLIBC_RETVAL_SUCCESS) {
        printf("--->[%d]", *return_data);
    }

    retval = olibc_list_iterator_destroy(&iter_hdl);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to destroy iterator %s",
                olibc_retval_get_string(retval));
    }
    printf("\n");
    return CPARSER_OK;
}
