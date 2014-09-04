/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __ANRA_DB_H__
#define __ANRA_DB_H__

#include "../al/an_types.h"
#include "../al/an_avl.h"

typedef enum an_anra_color_device_label_ {
    AN_COLOR_UNKNOWN = 0,
    AN_WHITELIST_DEVICE,
    AN_QUARANTINE_TO_WHITELIST_DEVICE,
} an_anra_color_device_label;


typedef struct an_accepted_device_t_ {
    an_avl_node_t avlnode;
    
    an_udi_t udi;
    uint8_t device_suffix;
    uint8_t *device_id; 
    an_addr_t addr;
    uint32_t router_id;
} an_accepted_device_t;

typedef struct an_anra_color_device_t_ {
    an_avl_node_t avlnode;
    an_udi_t udi;
    an_anra_color_device_label label;
} an_anra_color_device_t;

typedef struct an_anra_quarantine_device_t_ {
    an_avl_node_t avlnode;
    an_udi_t udi;
    an_addr_t anproxy;
    an_iptable_t iptable;
} an_anra_quarantine_device_t;

an_accepted_device_t* an_accepted_device_alloc(void);
void an_accepted_device_free(an_accepted_device_t *member);

boolean an_accepted_device_db_insert(an_accepted_device_t *member);
boolean an_accepted_device_db_remove(an_accepted_device_t *member);
an_accepted_device_t* an_accepted_device_db_search(an_udi_t udi);

void an_accepted_device_db_walk(an_avl_walk_f func, void *args);
void an_accepted_device_db_init(void);


/* Below set of functions defined for Whitelist MEMBER DB - 
        -Which is list of nodes that are registered with ANRA */
an_anra_color_device_t* an_anra_color_device_alloc(void);
void an_anra_color_device_free(an_anra_color_device_t *member);

boolean an_anra_color_device_db_insert(an_anra_color_device_t *member);
boolean an_anra_color_device_db_remove(an_anra_color_device_t *member);
an_anra_color_device_t* an_anra_color_device_db_search(an_udi_t udi);

void an_anra_color_device_db_walk(an_avl_walk_f func, void *args);
void an_anra_color_device_db_init(an_anra_color_device_label label);

/* Below set of functions defined for Quarantine DB - 
        -Which is list of nodes that are blocked at ANRA */
an_anra_quarantine_device_t* an_anra_quarantine_device_alloc(void);
void an_anra_quarantine_device_free(an_anra_quarantine_device_t *member);

boolean an_anra_quarantine_device_db_insert(an_anra_quarantine_device_t 
                                                                *member);
boolean an_anra_quarantine_device_db_remove(an_anra_quarantine_device_t 
                                                                *member);
an_anra_quarantine_device_t* an_anra_quarantine_device_db_search(an_udi_t udi);

void an_anra_quarantine_device_db_walk(an_avl_walk_f func, void *args);
void an_anra_quarantine_device_db_init(void);
an_walk_e an_accepted_device_db_init_cb(an_avl_node_t *node, void *args);
an_walk_e an_anra_color_device_db_init_cb(an_avl_node_t *node, void *args);
an_walk_e an_anra_quarantine_device_db_init_cb(an_avl_node_t *node, void *args);


#endif
