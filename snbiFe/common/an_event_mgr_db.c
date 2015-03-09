/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "an_event_mgr_db.h"

static const uint8_t *an_event_string [] = {

    "INVALID Event",

    "UDI AVAILABLE Event ",
    "SUDI AVAILABLE Event ",
    "SYSTEM-CONFIGURED Event ",
    "INTERFACE UP Event ",
    "INTERFACE DOWN Event ",
    "INTERFACE ACTIVATE Event ",
    "INTERFACE DEACTIVATE Event ",
    "INTERFACE ERASED Event ",
    "INTERFACE Autonomic Init Event ",
    "INTERFACE Autonomic Uninit Event ",
    "REGISTRAR UNINIT ",
    "REGISTRAR LIVE PENDING Event ",
    "REGISTRAR SHUT PENDING Event ",
    "REGISTRAR DELETE PENDING Event ",
    "REGISTRAR UP LOCALLY Event ",
    "REGISTRAR SHUT Event ",
    "REGISTRAR REACHABLE Event ",
    "DEVICE BOOTSTRAP Event ",
    "SERVICE DISCOVERY SRVC RECEIVED Event ",
    "SERVICE DISCOVERY SRVC RESOLVED Event ",
    "SERVICE DISCOVERY HOST RESOLVED Event ",
    "ACP INIT Event ",
    "ACP UNINIT Event ",
    "ACP PRE UNINIT Event ",
    "ACP ON LINK Created Event ",
    "ACP ON LINK REMOVED Event ",
    "TIMER NI CERT REQUEST EXPIRED Event ",
    "TIMER HELLO REFRESH EXPIRED Event ",
    "TIMER ANR BS RETRY EXPIRED Event ",
    "TIMER CERT REVOKE CHECK EXPIRED Event ",
    "TIMER NBR CERT REVALIDATE EXPIRED Event ",
    "TIMER NBR CERT RENEW EXPIRED Event ",
    "TIMER MY CERT RENEW EXPIRED Event ",
    "TIMER GENERIC EXPIRED Event ",
    "TIMER NBR LINK CLEANUP EXPIRED Event ",
    "NBR LINK ADD Event ",
    "NBR ADD Event",
    "NBR REFRESHED Event",
    "NBR PARAMS CAHNGED Event",
    "NBR INSIDE DOMAIN Event ",
    "NBR OUTSIDE DOMAIN Event ",
    "NBR CERT VALIDITY EXPIRED Event ",
    "DOMAIN DEVICE CERT EXPIRED Event ",
    "DOMAIN DEVICE CERT RENEWED Event ",
    "VALIDATION CERT RESPONSE Event",
    "CLOCK SYNCHRONISED Event ",
    "DEVICE CERT ENROLL SUCCESS Event ",
    "DEVICE CERT ENROLL FAILED Event ",
    "MAX Event ",
};

static const uint8_t *an_event_consumer_string [] = {
    
    "INVALID Module",
    
    "CD Module ",
    "ND Module ",
    "SERVICE DISCOVERY Module ",
    "BS Module ",
    "ACP Module ",
    "IDP Module ",
    "REGISTRAR Module ",
    "INTENT Module ",
    "CONFIG DOWNLOAD Module ",
    "INTERFACE Manager Module ",
    "AN UTILS Module ",
    "MAX Module ",
};  

boolean
an_event_validate_event_type (an_event_e event_type)
{
    if ((event_type > AN_EVENT_INVALID) && (event_type < AN_EVENT_MAX)) {
        return (TRUE);
    }
    return (FALSE);
}

boolean
an_event_validate_event_consumer (an_modules_e module_name)
{
    if ((module_name > AN_MODULE_INVALID) && (module_name < AN_MODULE_MAX)) {
        return (TRUE);
    }
    return (FALSE);
}

const uint8_t * an_get_event_str(an_event_e event)
{
    if (!an_event_validate_event_type(event)){
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sEvent type is invalid."
                     "Failed to return Event string",
                      an_bs_event);
        return (an_event_string[0]);
    }
    return (an_event_string[event]);
}

const uint8_t * an_get_event_consumer_str(an_modules_e module)
{
    if (!an_event_validate_event_consumer(module)){
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sModule type is invalid."
                     "Failed to return Event Consumer String",
                      an_bs_event);
        return (an_event_consumer_string[module]) ;
    }

    return (an_event_consumer_string[module]);
}

/* Memory allocation for Event Consumer information */
an_event_consumer_t *
an_event_consumer_alloc_node (void)
{
    an_event_consumer_t *consumer_data = NULL;

    consumer_data = an_malloc_guard(sizeof(an_event_consumer_t),
                    "AN Event Consumer node");
    if (consumer_data == NULL) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                     "\n%sMemory Alloc failed for the AN Event Consumer DB" 
                     " entry", an_bs_event);
        return (consumer_data);
    }

    an_memset(consumer_data, 0, sizeof(an_event_consumer_t));
    return (consumer_data);
}
/* Memory De-allocation for Event Consumer information */
void
an_event_free_consumer_node (an_event_consumer_t *consumer_data)
{
    an_free_guard(consumer_data);
}

/* To create Event and Event Consumer related db's */
boolean
an_event_db_create (an_list_t **ptr_data)
{
    if (!(*ptr_data)) {
        if (AN_CERR_SUCCESS != an_list_create(ptr_data,
                              "AN Event DB")) {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sEvent DB creation failed",
                         an_bs_event);
            return (FALSE);
        }
        else {
            DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sEvent DB created succesfully",
                         an_bs_event);
            return (TRUE);
        }
    }
    return (FALSE);
}

/* To Walk thro' the Event and Event Consumer related db's */
an_cerrno
an_event_db_walk (an_list_t *list, an_list_walk_handler callback_func,
                     void *event_data)
{
    an_cerrno ret;
    //walk the list and pass the list elem to the callback func
    ret = AN_CERR_POSIX_ERROR(an_list_walk(list,
                callback_func,
                event_data));
    return (ret);
}

/* To Insert Event Consumer info into Event Consumer DB's */
boolean
an_event_consumer_db_insert (an_list_t *list, an_event_consumer_t *consumer_data,
                    an_modules_e consumer, fn_handler handler)
{
    if (handler == NULL) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%s Handler parameter invalid while trying to"
                    " add Event Consumer info to Event Consumer DB", an_bs_event);
        return (FALSE);
    }

    if (!an_list_is_valid(list)) {
       DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sInvalid Event Consumer DB while trying to insert" 
                    " a node", an_bs_event);
       return (FALSE);
    }

    consumer_data->consumer = consumer; 
    consumer_data->handler = handler;

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                  "\n%s Adding Event Consumer Node to the Event Consumer DB"
                    , an_bs_event);

    an_list_enqueue_node(list, consumer_data);
    return (TRUE);
}

/* To remove Event Comsumer info from Event Consumer DB's and free memory*/
an_cerrno
an_event_consumer_node_remove (an_list_t *list, const an_list_element_t *current,
                    an_event_consumer_t *consumer_data)
{
    if ((NULL == list) || (NULL == current) || (NULL == consumer_data)) {
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%s Removing Event Consumer data from Event Consumer" 
                        " DB", an_bs_event);

    if (!an_list_remove(list, (an_list_element_t *)current, consumer_data)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%s Failed to Remove Node from Event Consumer DB",
                    an_bs_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%s Successfully removed Node from Event Consumer DB",
                    an_bs_event);
    an_event_free_consumer_node(consumer_data);
    
    return (AN_CERR_SUCCESS);
}

static an_cerrno
an_event_remove_and_free_all_consumer_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_event_consumer_t *curr_data = NULL;
    an_cerrno ret = AN_CERR_SUCCESS;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params while destroying "
                     "Event Consumer DB", an_bs_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }
    curr_data = (an_event_consumer_t *)current->data;
    if (list && current) {
        ret = an_event_consumer_node_remove(list, current, curr_data);
        return ret;
    }
    return (AN_CERR_V_FATAL(0, 0, EINVAL));
}

/* Remove all nodes in the Event Consumer DB and free all memory */
an_cerrno
an_event_consumer_db_destroy (an_list_t *list)
{
    an_cerrno ret;
    /* Walk through the list of consumer db and free all memory */
     DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sWalking through Consumer DB to destroy all the consumer info",
                 an_bs_event);

    ret = an_event_db_walk(list, an_event_remove_and_free_all_consumer_cb,
                              NULL);
    if (an_list_is_valid(list)) {
        ret = an_list_destroy(&list);
        if (AN_CERR_SUCCESS != ret) {
             DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                          "\n%sEvent Consumer DB destroy failed",
                          an_bs_event);
         } else {
             DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                          "\n%sEvent Consumer DB destroy successful",
                          an_bs_event);
             list = NULL;
         }
    }
    return (ret); 
}

static an_cerrno
an_event_consumer_node_remove_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_event_consumer_t *consumer_data = NULL;
    an_event_consumer_t *consumer_curr_data = NULL;

    consumer_data = (an_event_consumer_t *) context;

    if (current == NULL || list == NULL || consumer_data == NULL)    {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull Input params to remove the Event Consumer" 
                     " info from Event Consumer DB", an_bs_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    consumer_curr_data = (an_event_consumer_t *) current->data;

    if (list && current) {
        if ( consumer_data->consumer == consumer_curr_data->consumer) {
            an_event_consumer_node_remove(list, current, consumer_curr_data);
        }
       return (AN_CERR_SUCCESS);
    }

    return (AN_CERR_V_FATAL(0, 0, EINVAL));
}


/* Remove a node in the Event Consumer DB and free memory */
void
an_event_consumer_node_db_remove (an_list_t *list, an_event_consumer_t *consumer_data)
{
    if (list == NULL || consumer_data == NULL)    {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sInvalid params while trying to remove Event Consumer"
                     "info from Event Consumer DB ", an_bs_event);
        return;
    }

    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sWalking the Event Consumer DB to remove the Event Consumer" 
                 " data." , an_bs_event);

    an_event_db_walk(list, an_event_consumer_node_remove_cb,
                             consumer_data);

    if (an_list_is_empty(list)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sEvent Consumer DB is empty", an_bs_event);
    }

    return;
}

static int
an_event_consumer_search_cb (void *data1, void *data2)
{
    an_event_consumer_t *ctx1 = NULL;
    an_event_consumer_t *ctx2 = NULL;

    if ((!data1) || (!data2)) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sInvalid params, consumer data search"
                        " in Event consumer DB ",
                      an_bs_event);
        return (-1);
    }
    ctx1 = (an_event_consumer_t *)data1;
    ctx2 = (an_event_consumer_t *)data2;

    if (ctx1->consumer == ctx2->consumer) {
       return(0);
    }
    return(1);
}

/* To search for a node in Event Consumer DB */
an_event_consumer_t*
an_event_consumer_db_search(an_list_t *list, an_modules_e module_name)
{
    an_event_consumer_t goal = {};
    an_event_consumer_t *found_data = NULL;

    if (!module_name) {
        return (NULL);
    }

    goal.consumer = module_name;
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                 "\nSearching in Event Consumer DB ");
    found_data = (an_event_consumer_t *) an_list_lookup_node(list, NULL,
            (void *)&(goal), an_event_consumer_search_cb);

    return (found_data);
}

/* To show the contents of Event consumer DB */
an_cerrno
an_event_show_event_consumer_db_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context)
{
    an_event_consumer_t *curr_data = NULL;
    an_cerrno ret = AN_CERR_SUCCESS;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params to Event consumer DB"
                     " while showing contents", an_bs_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }

    curr_data = (an_event_consumer_t *)current->data;
    if (list && current) {
        printf ("\n     Module = %s ", 
        an_get_event_consumer_str(curr_data->consumer));
    }

    return ret;

}

/* To show the contents of Event and Event Consumer DB */
void
an_event_show_event_db (void)
{
    uint32_t i = 0;
    for (i = 1; i < AN_EVENT_MAX; i++) {
        printf ("\nEvent = %s", an_get_event_str(i));
        an_event_db_walk(an_event_consumer_ptr[i].an_event_consumer_db, 
                    an_event_show_event_consumer_db_cb, NULL);
    }
}

/* To Initialise Event DB's */
void
an_event_db_init (void)
{
    uint32_t i = 0;
    for (i = 1; i < AN_EVENT_MAX; i++) {
        an_event_consumer_ptr[i].an_event_consumer_db = NULL;
        an_event_db_create(&an_event_consumer_ptr[i].an_event_consumer_db);
    }

}

/* To Un-initialise Event DB's */
void
an_event_db_uninit (void)
{
    uint32_t i = 0;
    for (i = 1; i < AN_EVENT_MAX; i++) {
        if (an_event_consumer_ptr[i].an_event_consumer_db) {
            an_event_consumer_db_destroy(an_event_consumer_ptr[i].an_event_consumer_db);
        }
    }
}

/* Modules can register for an event to get 
    callback function when event occurs*/
void
an_event_register_consumer (an_modules_e module, 
                        an_event_e an_event, fn_handler handler)

{   
    an_event_consumer_t *consumer_data = NULL;

    if (!an_event_validate_event_type(an_event)){
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sEvent type is invalid."
                     "Failed to add Event consumer info in Event Consumer DB",
                      an_bs_event);
        return;
    }
    if (!an_event_validate_event_consumer(module)){
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sModule type is invalid."
                     "Failed to remove Event Consumer info from Event Consumer DB",
                      an_bs_event);
        return;
    }
    
    consumer_data = an_event_consumer_db_search
            (an_event_consumer_ptr[an_event].an_event_consumer_db, module);
    if (consumer_data) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sEvent Consumer %s is already registered for the " 
                     "event %s", an_get_event_consumer_str(module),
                     an_get_event_str(an_event),an_bs_event);
        return;
    }

    consumer_data = an_event_consumer_alloc_node();
    if (consumer_data) {
        an_event_consumer_db_insert (an_event_consumer_ptr[an_event].an_event_consumer_db, 
                consumer_data, module, handler);
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to allocate memory for Event Consumer %s " 
                     "while trying to register for event %s ",
                     an_get_event_consumer_str(module), 
                     an_get_event_str(an_event), an_bs_event);
    }
}  

/* Modules can unregister for an event, to not get 
    callback function when event occurs*/
void
an_event_unregister_consumer_eventhandler (an_modules_e module, 
                                            an_event_e an_event)
{
    an_event_consumer_t *consumer_data = NULL;
    
    if (!an_event_validate_event_type(an_event)){
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sEvent type is invalid."
                     "Failed to add Event consumer info in Event Consumer DB",
                      an_bs_event);
        return;
    }
    if (!an_event_validate_event_consumer(module)){
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sModule type is invalid."
                     "Failed to remove Event Consumer info from Event Consumer DB",
                      an_bs_event);
        return;
    }
    consumer_data = an_event_consumer_db_search 
                (an_event_consumer_ptr[an_event].an_event_consumer_db, module);
    if (consumer_data) {
        an_event_consumer_node_db_remove(
                    an_event_consumer_ptr[an_event].an_event_consumer_db, 
                    consumer_data);
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sEvent Consumer %s info deleted from Event Consumer DB",
                      an_get_event_consumer_str(module), an_bs_event);
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sEvent Consumer %s info is not present in Event Consumer DB",
                      an_get_event_consumer_str(module), an_bs_event);
    }
}

static an_cerrno
an_event_notify_consumers_cb (an_list_t *list,
              const an_list_element_t *current,
              an_list_element_t *next, void *context) 
{
    an_event_consumer_t *curr_data = NULL;
    an_cerrno ret = AN_CERR_SUCCESS;

    if (current == NULL || list == NULL)    {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull input params while notifying "
                     "Event Consumer about event", an_bs_event);
        return (AN_CERR_V_FATAL(0, 0, EINVAL));
    }
    curr_data = (an_event_consumer_t *)current->data;
    if (list && current) {
        curr_data->handler(context);
        return ret;
    }
    return (AN_CERR_V_FATAL(0, 0, EINVAL));

}

/* Event notification function*/
void
an_event_notify_consumers (an_event_e an_event, void *context)
{
    if (!an_event_validate_event_type(an_event)){
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sEvent type is invalid."
                     "Failed to notify Event consumer",
                      an_bs_event);
        return;
    }
    if (&an_event_consumer_ptr[an_event].an_event_consumer_db) {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_INFO, NULL,
                     "\n%sNotifying Event Consumers registered for the event %s",
                      an_bs_event, an_get_event_str(an_event));
        an_event_db_walk(an_event_consumer_ptr[an_event].an_event_consumer_db, 
                        an_event_notify_consumers_cb, context);
    } else {
        DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sThere are no Event Consumers registered for the event " 
                     "%s", an_bs_event, an_get_event_str(an_event));
    }
}
