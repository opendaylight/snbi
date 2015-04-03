/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <stdio.h>
#include <an_event_mgr.h>
#include <an_if_mgr.h>
#include <stdio.h>
#include <unistd.h>
#include <an_types.h>
#include <an_str.h>
#include <cparser.h>
#include <cparser_tree.h>

cparser_result_t
cparser_cmd_snbi_start (cparser_context_t *context)
{
    printf("\n*********Starting Autonomic Process************\n");
    an_event_db_init();
    an_autonomic_enable();
    return;
}

cparser_result_t
cparser_cmd_snbi_stop (cparser_context_t *context)
{
    an_autonomic_disable();
    printf("\n*************Ending Autonomic Process**********\n");
    return;
}

cparser_result_t 
cparser_cmd_no_snbi_discovery (cparser_context_t *context)
{
}

cparser_result_t
cparser_cmd_snbi_discovery (cparser_context_t *context)
{
    int no = 0;
    an_if_t ifhndl = 0;
    an_if_info_t *an_if_info = NULL;

// Replace netio0 with av[2] and av[1] resply after taking input from user
    if (no) {
       ifhndl = if_nametoindex("netio0");
    }
    if (!no) {
       ifhndl = if_nametoindex("netio0");
    }
    if (!ifhndl) {
        return;
    }
    an_if_info = an_if_info_db_search(ifhndl, TRUE);
    if (!an_if_info) {
        return;
    }
    
    if (!no) {
        printf("\n [SNBI_printf] Enabling Discovery on Intf...!");
        an_nd_set_preference(ifhndl, AN_ND_CLIENT_CLI, AN_ND_CFG_ENABLED);
        an_nd_start_on_interface(ifhndl);
    } else {
        printf("\n [SNBI_printf] Disabling Discovery on Interface...!");
        an_nd_set_preference(ifhndl, AN_ND_CLIENT_CLI, AN_ND_CFG_DISABLED);
        an_nd_stop_on_interface(ifhndl);
    }

//    return 0;
}


cparser_result_t 
cparser_cmd_snbi_interface_start (cparser_context_t *context)
{
    an_if_t ifhndl = 0;
    an_if_info_t *an_if_info = NULL;

// Replace netio0 with av[1] after taking input from user
    ifhndl = if_nametoindex("netio0");
    if (!ifhndl) {
        return;
    }
    an_if_info = an_if_info_db_search(ifhndl, TRUE);
    if (!an_if_info) {
        return;
    }

/*  if (an_if_is_cfg_autonomic_enabled(an_if_info)) {
        printf("\n [SRK_printf] Autonomic already enabled on interface.. return...!");
        return;
        }
*/
printf("\n [SRK_printf] Setting interface mode autonomic...!");
    an_if_set_cfg_autonomic_enable(an_if_info, TRUE);
    an_if_autonomic_enable(ifhndl);
    return;
}

cparser_result_t 
cparser_cmd_snbi_interface_stop (cparser_context_t *context)
{
    an_if_t ifhndl = 0;
    an_if_info_t *an_if_info = NULL;

// Replace netio0 with av[1] after taking input from user
    ifhndl = if_nametoindex("netio0");
    if (!ifhndl) {
        return;
    }
    an_if_info = an_if_info_db_search(ifhndl, TRUE);
    if (!an_if_info) {
        return;
    }
    if (!an_if_is_cfg_autonomic_enabled(an_if_info)) {
        return; 
    }
printf("\n [SRK_printf] Unsetting interface mode autonomic...!");
    an_if_set_cfg_autonomic_enable(an_if_info, FALSE);
    an_if_autonomic_disable(ifhndl);
    return;
}

cparser_result_t
cparser_cmd_quit (cparser_context_t *context)
{
    return cparser_quit(context->parser);
}

static cparser_result_t
cparser_cmd_enter_privileged_mode (cparser_t *parser, char *buf, int buf_size)
{
    if (strncmp(buf, "snbi", buf_size)) {
        printf("\nPassword incorrect. Should enter 'snbi'.\n");
    } else {
        printf("\nEnter privileged mode.\n");
        cparser_set_privileged_mode(parser, 1);
    }
    return CPARSER_OK;
}


cparser_result_t
cparser_cmd_enable_privileged_mode (cparser_context_t *context)
{
    char passwd[100];
    int rc;

    if (cparser_is_in_privileged_mode(context->parser)) {
        printf("Already in privileged mode.\n");
        return CPARSER_NOT_OK;
    }

    /* Request privileged mode password */
    rc = cparser_user_input(context->parser, 
                            "Enter password (Enter: 'snbi'): ", 0,
                            passwd, sizeof(passwd), 
                            cparser_cmd_enter_privileged_mode);
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_disable_privileged_mode (cparser_context_t *context)
{
    if (!cparser_is_in_privileged_mode(context->parser)) {
        printf("Not in privileged mode.\n");
        return CPARSER_NOT_OK;
    }

    cparser_set_privileged_mode(context->parser, 0);
    return CPARSER_OK;
}
