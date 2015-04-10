/*
 * Debug/logg cli
 *
 * Vijay Anand R
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <cparser.h>
#include <cparser_tree.h>
#include <an_logger.h>

static
an_log_type_e an_clisim_get_nd_log_type (char *type_str)
{

    if (!strcasecmp(type_str, "Database")) {
        return (AN_LOG_ND_DB);
    }
    
    if (!strcasecmp(type_str, "Events")) {
        return (AN_LOG_ND_EVENT);
    }

    if (!strcasecmp(type_str, "Packets")) {
        return (AN_LOG_ND_PACKET);
    }
    return AN_LOG_ND_ALL;
}

static
an_log_type_e an_clisim_get_bs_log_type (char *type_str)
{

    if (!strcasecmp(type_str, "Events")) {
        return (AN_LOG_BS_EVENT);
    }

    if (!strcasecmp(type_str, "Packets")) {
        return (AN_LOG_BS_PACKET);
    }
    return AN_LOG_BS_ALL;
}

static 
an_debug_level_e an_clisim_get_debug_level (char *level_str)
{
    if (!strcasecmp(level_str, "info")) {
        return (AN_DEBUG_INFO);
    }
    if (!strcasecmp(level_str,"moderate")) {
        return (AN_DEBUG_MODERATE);
    }
    if (!strcasecmp(level_str, "sev")) {
        return AN_DEBUG_SEVERE;
    }
    return AN_DEBUG_MAX;
}

cparser_result_t
cparser_cmd_snbi_debug_neighbor_discovery_type_level 
                                          (cparser_context_t *context,
                                           char **type_ptr,
                                           char **level_ptr)
{
    an_log_type_e type;
    an_debug_level_e lev;

    type = an_clisim_get_nd_log_type(*type_ptr);
    lev = an_clisim_get_debug_level(*level_ptr);
    an_config_debug_log(type, lev, TRUE);
    return (CPARSER_OK);
}

cparser_result_t
cparser_cmd_snbi_no_debug_neighbor_discovery_type_level
                                          (cparser_context_t *context,
                                           char **type_ptr,
                                           char **level_ptr)
{
    an_log_type_e type;
    an_debug_level_e lev;

    type = an_clisim_get_nd_log_type(*type_ptr);
    lev = an_clisim_get_debug_level(*level_ptr);
    an_config_debug_log(type, lev, FALSE);
    return (CPARSER_OK);
}

cparser_result_t
cparser_cmd_snbi_debug_bootstrap_type_level
                                          (cparser_context_t *context,
                                           char **type_ptr,
                                           char **level_ptr)
{
    an_log_type_e type;
    an_debug_level_e lev;

    type = an_clisim_get_bs_log_type(*type_ptr);
    lev = an_clisim_get_debug_level(*level_ptr);
    an_config_debug_log(type, lev, TRUE);
    return (CPARSER_OK);
}

cparser_result_t
cparser_cmd_snbi_no_debug_bootstrap_type_level
                                          (cparser_context_t *context,
                                           char **type_ptr,
                                           char **level_ptr)
{
    an_log_type_e type;
    an_debug_level_e lev;

    type = an_clisim_get_bs_log_type(*type_ptr);
    lev = an_clisim_get_debug_level(*level_ptr);
    an_config_debug_log(type, lev, FALSE);
    return (CPARSER_OK);
}
