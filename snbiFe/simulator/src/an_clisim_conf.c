/*
 * Vijay Anand R <vanandr@cisco.com>
 *
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <an_str.h>
#include <stdlib.h>
#include <cparser.h>
#include <an_types.h>
#include <an_if_mgr.h>
#include <cparser_tree.h>
#include <an_event_mgr.h>
#include <an_conf_linux.h>

cparser_result_t 
cparser_cmd_clear_screen (cparser_context_t *context)
{
    system("clear");
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_configure_enable (cparser_context_t *context)
{
    if (!an_enable_cmd_handler()) {
        return CPARSER_NOT_OK;
    }

    return (CPARSER_OK);
}

cparser_result_t
cparser_cmd_configure_disable (cparser_context_t *context)
{
    if (!an_disable_cmd_handler()) {
        return CPARSER_NOT_OK;
    }

    return (CPARSER_OK);
}

cparser_result_t
cparser_cmd_configure (cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    snprintf(prompt, CPARSER_MAX_PROMPT, "snbi.d (config) > ");
    return (cparser_submode_enter(context->parser, NULL, prompt)); 
}

cparser_result_t
cparser_cmd_configure_quit (cparser_context_t *context)
{
    assert(context && context->parser);
    return cparser_submode_exit(context->parser);
}

cparser_result_t
cparser_cmd_test (cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    snprintf(prompt, CPARSER_MAX_PROMPT, "snbi.d (test) > ");
    return (cparser_submode_enter(context->parser, NULL, prompt));
}

cparser_result_t
cparser_cmd_test_quit (cparser_context_t *context)
{
    assert(context && context->parser);
    return cparser_submode_exit(context->parser);
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
