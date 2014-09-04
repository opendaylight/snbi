/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "../al/an_types.h"
#include "../al/an_mem.h"
#include "../al/an_str.h"
#include "an_anra_db.h"
#include "../al/an_logger.h"

an_avl_tree an_accepted_device_tree;
an_accepted_device_t* an_accepted_device_db = NULL;
static an_mem_chunkpool_t *an_accepted_device_pool = NULL;
static const uint16_t AN_ACCEPTED_DEVICE_POOL_SIZE = 64;

an_avl_tree an_anra_color_device_tree;
an_anra_color_device_t* an_anra_color_device_db = NULL;
static an_mem_chunkpool_t *an_anra_color_device_pool = NULL;
static const uint16_t AN_ANRA_COLOR_DEVICE_POOL_SIZE = 64;
 
an_avl_tree an_anra_quarantine_device_tree; 
an_anra_quarantine_device_t* an_anra_quarantine_device_db = NULL;
static an_mem_chunkpool_t *an_anra_quarantine_device_pool = NULL;
static const uint16_t AN_ANRA_QUARANTINE_DEVICE_POOL_SIZE = 64;

an_accepted_device_t* 
an_accepted_device_alloc (void)
{
    an_accepted_device_t *member = NULL;

    if (!an_accepted_device_pool) {
        /* Allocate ANRA Accepted Device chunk pool */
        an_accepted_device_pool = an_mem_chunkpool_create(
                              sizeof(an_accepted_device_t),
                              AN_ACCEPTED_DEVICE_POOL_SIZE, 
                              "AN Accepted Device ChunkPool");
    }

    /* Try to allocate a ANRA Accepted Device */
    member = an_mem_chunk_malloc(an_accepted_device_pool);
    if (!member) {
        if (an_mem_chunkpool_destroyable(an_accepted_device_pool)) {
            an_mem_chunkpool_destroy(an_accepted_device_pool);
            an_accepted_device_pool = NULL;
        }
        return (NULL);
    }

    return (member);
} 

void
an_accepted_device_free (an_accepted_device_t *member)
{
    if (!member) {
        return;
    }

    if (member->udi.data) {
        an_free_guard(member->udi.data);
    }
    if (member->device_id) {
        an_free_guard(member->device_id);
    }
    
    an_mem_chunk_free(&an_accepted_device_pool, member);
}

an_avl_compare_e 
an_accepted_device_compare (an_avl_node_t *node1, an_avl_node_t *node2)
{
    an_accepted_device_t *member1 = (an_accepted_device_t *)node1;
    an_accepted_device_t *member2 = (an_accepted_device_t *)node2;
    int32_t comp = 0;

    if (!member1 && !member2) {
        return (AN_AVL_COMPARE_EQ);
    } else if (!member1) {
        return (AN_AVL_COMPARE_LT);
    } else if (!member2) {
        return (AN_AVL_COMPARE_GT);
    }

    if (member1->udi.len < member2->udi.len) {
        return (AN_AVL_COMPARE_LT);
    } else if (member1->udi.len > member2->udi.len) {
        return (AN_AVL_COMPARE_GT);
    } else { 
        comp = an_strcmp(member1->udi.data, member2->udi.data);
        if (comp < 0) {
            return (AN_AVL_COMPARE_LT);
        } else if (comp > 0) {
            return (AN_AVL_COMPARE_GT);
        } else {
            return (AN_AVL_COMPARE_EQ);
        }
    }
}

boolean
an_accepted_device_db_insert (an_accepted_device_t *member)
{
    if (!member) {
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sInserting member %s into accepted device DB", an_ra_db, 
                 member->udi.data);
    return (an_avl_insert_node((an_avl_top_p *)&an_accepted_device_db,
                  (an_avl_node_t *)member, an_accepted_device_compare,
                  &an_accepted_device_tree));
}

boolean
an_accepted_device_db_remove (an_accepted_device_t *member)
{
    if (!member) {
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sRemoving device %s from accepted device DB", an_ra_db,
                 member->udi.data);
    an_avl_remove_node((an_avl_top_p *)&an_accepted_device_db,
                  (an_avl_node_t *)member, an_accepted_device_compare,
                  &an_accepted_device_tree);

    return (TRUE);
}

an_accepted_device_t *
an_accepted_device_db_search (an_udi_t udi)
{
    an_accepted_device_t goal_member = {};
    an_accepted_device_t *member = NULL;

    an_avl_node_t *avl_type  = (an_avl_node_t *)&goal_member;
    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sAN Registrar searching device [%s] in accepted device DB", 
                 an_ra_db, udi.data);
    an_memcpy(&goal_member.udi, &udi, sizeof(an_udi_t));
    member = (an_accepted_device_t *)
          an_avl_search_node((an_avl_top_p)an_accepted_device_db,
                        avl_type, an_accepted_device_compare, 
                        &an_accepted_device_tree);

    return (member);
}

void
an_accepted_device_db_walk (an_avl_walk_f walk_func, void *args)
{
    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sWalking accepted device DB", an_ra_db);
    an_avl_walk_all_nodes((an_avl_top_p *)&an_accepted_device_db,
                          walk_func,
                          an_accepted_device_compare, args, 
                          &an_accepted_device_tree);
}

an_walk_e
an_accepted_device_db_init_cb (an_avl_node_t *node, void *args)
{
    an_accepted_device_t *member = (an_accepted_device_t *)node;

    if (!member) {
        return (AN_WALK_FAIL);
    }

    if (member->udi.data) {
        an_free_guard(member->udi.data);
        member->udi.data = NULL;
    }

    if (member->device_id) {
        an_free_guard(member->device_id);
        member->device_id = NULL;
    }

    an_accepted_device_db_remove(member);
    an_accepted_device_free(member);

    return (AN_WALK_SUCCESS);
}

void
an_accepted_device_db_init (void)
{
    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sInitializing Accepted Device DB", an_ra_db);
    an_accepted_device_db_walk(an_accepted_device_db_init_cb, NULL);
}

an_anra_color_device_t*
an_anra_color_device_alloc (void)
{
    an_anra_color_device_t *color_device = NULL;

    if (!an_anra_color_device_pool) {
        /* Allocate ANRA Color Device chunk pool */
        an_anra_color_device_pool =
                an_mem_chunkpool_create(sizeof(an_anra_color_device_t),
                AN_ANRA_COLOR_DEVICE_POOL_SIZE, "AN Color Device ChunkPool");
    }

    /* Try to allocate a ANRA Color Device */
    color_device = an_mem_chunk_malloc(an_anra_color_device_pool);
    if (!color_device) {
        if (an_mem_chunkpool_destroyable(an_anra_color_device_pool)) {
            an_mem_chunkpool_destroy(an_anra_color_device_pool);
            an_anra_color_device_pool = NULL;
        }
        return (NULL);
    }

    return (color_device);
}

void
an_anra_color_device_free (an_anra_color_device_t *color_device)
{
    if (!color_device) {
        return;
    }

    if (color_device->udi.data) {
        an_free_guard(color_device->udi.data);
    }

    an_mem_chunk_free(&an_anra_color_device_pool, color_device);
}

an_avl_compare_e
an_anra_color_device_compare (an_avl_node_t *node1, an_avl_node_t *node2)
{
    an_anra_color_device_t *member1 = (an_anra_color_device_t *)node1;
    an_anra_color_device_t *member2 = (an_anra_color_device_t *)node2;
    int32_t comp = 0;

    if (!member1 && !member2) {
        return (AN_AVL_COMPARE_EQ);
    } else if (!member1) {
        return (AN_AVL_COMPARE_LT);
    } else if (!member2) {
        return (AN_AVL_COMPARE_GT);
    }

    if (member1->udi.len < member2->udi.len) {
        return (AN_AVL_COMPARE_LT);
    } else if (member1->udi.len > member2->udi.len) {
        return (AN_AVL_COMPARE_GT);
    } else {
        comp = an_strcmp(member1->udi.data, member2->udi.data);
        if (comp < 0) {
            return (AN_AVL_COMPARE_LT);
        } else if (comp > 0) {
            return (AN_AVL_COMPARE_GT);
        } else {
            return (AN_AVL_COMPARE_EQ);
        }
    }
}

boolean
an_anra_color_device_db_insert (an_anra_color_device_t *color_device)
{
    if (!color_device || !color_device->udi.data) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sNull Udi data for the colored device", an_ra_db);
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                  "\n%sInserting device %s into color device DB", an_ra_db,
                  color_device->udi.data);
    return (an_avl_insert_node((an_avl_top_p *)&an_anra_color_device_db,
                  (an_avl_node_t *)color_device, 
                   an_anra_color_device_compare, &an_anra_color_device_tree)); 
}

boolean
an_anra_color_device_db_remove (an_anra_color_device_t *color_device)
{
    if (!color_device) {
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                 "\n%sRemoving device %s from color device DB", an_ra_db, 
                 color_device->udi.data);
    an_avl_remove_node((an_avl_top_p *)&an_anra_color_device_db,
                  (an_avl_node_t *)color_device, 
                   an_anra_color_device_compare, &an_anra_color_device_tree); 

    return (TRUE);
}

an_anra_color_device_t *
an_anra_color_device_db_search (an_udi_t udi)
{
    an_anra_color_device_t goal_member = {};
    an_anra_color_device_t *color_device = NULL;

    an_avl_node_t *avl_type  = (an_avl_node_t *)&goal_member;
    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sSearching device [%s] in color device DB", 
                 an_ra_db, udi.data);
    an_memcpy(&goal_member.udi, &udi, sizeof(an_udi_t));
    color_device = (an_anra_color_device_t *)
          an_avl_search_node((an_avl_top_p)an_anra_color_device_db,
                        avl_type, an_anra_color_device_compare, 
                        &an_anra_color_device_tree); 

    return (color_device);
}

void
an_anra_color_device_db_walk (an_avl_walk_f walk_func, void *args)
{
    an_avl_walk_all_nodes((an_avl_top_p *)&an_anra_color_device_db, 
                          walk_func, 
                          an_anra_color_device_compare, args, 
                          &an_anra_color_device_tree);    
}

an_walk_e
an_anra_color_device_db_init_cb (an_avl_node_t *node, void *args)
{
    an_anra_color_device_t *color_device = 
                (an_anra_color_device_t *)node;
    an_anra_color_device_label *label = NULL;

    if (!color_device || !args) {
        return (AN_WALK_FAIL);
    }
    
    label = (an_anra_color_device_label *)args;
    if (*label && (color_device->label !=  *label)) {
        return (AN_WALK_SUCCESS);
    }  

    if (color_device->udi.data) {
        an_free_guard(color_device->udi.data);
        color_device->udi.data = NULL;
    }

    an_anra_color_device_db_remove(color_device);
    an_anra_color_device_free (color_device);
    
    return (AN_WALK_SUCCESS);
}

void
an_anra_color_device_db_init (an_anra_color_device_label label)
{
    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                  "\n%sInitializing color device DB, walking all the nodes", 
                  an_ra_db);
    an_anra_color_device_db_walk(an_anra_color_device_db_init_cb, (void *)&label);
}

an_anra_quarantine_device_t*
an_anra_quarantine_device_alloc (void)
{
    an_anra_quarantine_device_t *quarantine_device = NULL;

    if (!an_anra_quarantine_device_pool) {
        /* Allocate ANRA Quarantine Device chunk pool */
        an_anra_quarantine_device_pool =
                an_mem_chunkpool_create(sizeof(an_anra_quarantine_device_t),
                AN_ANRA_QUARANTINE_DEVICE_POOL_SIZE, 
                "AN Quarantine Device ChunkPool");
    }

    /* Try to allocate a ANRA Quarantine Device */
    quarantine_device = an_mem_chunk_malloc(an_anra_quarantine_device_pool);
    if (!quarantine_device) {
        if (an_mem_chunkpool_destroyable(an_anra_quarantine_device_pool)) {
            an_mem_chunkpool_destroy(an_anra_quarantine_device_pool);
            an_anra_quarantine_device_pool = NULL;
        }
        return (NULL);
    }

    return (quarantine_device);
}

void
an_anra_quarantine_device_free (an_anra_quarantine_device_t *quarantine_device)
{
    if (!quarantine_device) {
        return;
    }

    if (quarantine_device->udi.data) {
        an_free_guard(quarantine_device->udi.data);
    }

    an_mem_chunk_free(&an_anra_quarantine_device_pool, quarantine_device);
}

an_avl_compare_e
an_quarantine_device_compare (an_avl_node_t *node1, an_avl_node_t *node2)
{
    an_anra_quarantine_device_t *member1 = (an_anra_quarantine_device_t *)node1;
    an_anra_quarantine_device_t *member2 = (an_anra_quarantine_device_t *)node2;
    int32_t comp = 0;

    if (!member1 && !member2) {
        return (AN_AVL_COMPARE_EQ);
    } else if (!member1) {
        return (AN_AVL_COMPARE_LT);
    } else if (!member2) {
        return (AN_AVL_COMPARE_GT);
    }

    if (member1->udi.len < member2->udi.len) {
        return (AN_AVL_COMPARE_LT);
    } else if (member1->udi.len > member2->udi.len) {
        return (AN_AVL_COMPARE_GT);
    } else {
        comp = an_strcmp(member1->udi.data, member2->udi.data);
        if (comp < 0) {
            return (AN_AVL_COMPARE_LT);
    } else if (comp > 0) {
            return (AN_AVL_COMPARE_GT);
        } else {
            return (AN_AVL_COMPARE_EQ);
        }
    }
}

boolean
an_anra_quarantine_device_db_insert (an_anra_quarantine_device_t 
                                                *quarantine_device)
{
    if (!quarantine_device || !quarantine_device->udi.data) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sNull Input Params for quarantine DB Insert", an_ra_db);
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                 "\n%sInserting device %s into quarantine device DB", an_ra_db,
                 quarantine_device->udi.data);
    return (an_avl_insert_node((an_avl_top_p *)&an_anra_quarantine_device_db,
                  (an_avl_node_t *)quarantine_device,
                   an_quarantine_device_compare,
                   &an_anra_quarantine_device_tree));
}

boolean
an_anra_quarantine_device_db_remove (an_anra_quarantine_device_t 
                                            *quarantine_device)
{
    if (!quarantine_device) {
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sRemoving device %s from quarantine device DB", an_ra_db, 
                 quarantine_device->udi.data);
    an_avl_remove_node((an_avl_top_p *)&an_anra_quarantine_device_db,
                  (an_avl_node_t *)quarantine_device,
                   an_quarantine_device_compare,
                   &an_anra_quarantine_device_tree);

    return (TRUE);
}

an_anra_quarantine_device_t *
an_anra_quarantine_device_db_search (an_udi_t udi)
{
    an_anra_quarantine_device_t goal_member = {};
    an_anra_quarantine_device_t *quarantine_device = NULL;

    an_avl_node_t *avl_type  = (an_avl_node_t *)&goal_member;
    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sSearching device %s in quarantine device DB",
                 an_ra_db, udi.data);
    an_memcpy(&goal_member.udi, &udi, sizeof(an_udi_t));
    quarantine_device = (an_anra_quarantine_device_t *)
          an_avl_search_node((an_avl_top_p)an_anra_quarantine_device_db,
                        avl_type, an_quarantine_device_compare,
                        &an_anra_quarantine_device_tree);
    
    return (quarantine_device);
}

void
an_anra_quarantine_device_db_walk (an_avl_walk_f walk_func, void *args)
{
    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sWalking quarantine device DB", an_ra_db);
    an_avl_walk_all_nodes((an_avl_top_p *)&an_anra_quarantine_device_db,
                          walk_func,
                          an_quarantine_device_compare, args, 
                          &an_anra_quarantine_device_tree);
}

an_walk_e
an_anra_quarantine_device_db_init_cb (an_avl_node_t *node, void *args)
{
    an_anra_quarantine_device_t *quarantine_device =
                (an_anra_quarantine_device_t *)node;

    if (!quarantine_device) {
        return (AN_WALK_FAIL);
    }

    if (quarantine_device->udi.data) {
        an_free_guard(quarantine_device->udi.data);
        quarantine_device->udi.data = NULL;
    }

    an_anra_quarantine_device_db_remove(quarantine_device);
    an_anra_quarantine_device_free(quarantine_device);

    return (AN_WALK_SUCCESS);
}

void
an_anra_quarantine_device_db_init (void)
{
    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sInitializing quarantine device DB", an_ra_db);
    an_anra_quarantine_device_db_walk(an_anra_quarantine_device_db_init_cb, 
                                                                      NULL);
}

