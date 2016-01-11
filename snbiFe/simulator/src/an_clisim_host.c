/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * Vijay Anand R <vanandr@cisco.com>
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <stdio.h>
#include <string.h>
#include <cparser.h>
#include <cparser_tree.h>
#include <assert.h>
#include <stdlib.h>

cparser_result_t
cparser_cmd_host (cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    snprintf(prompt, CPARSER_MAX_PROMPT, "snbi.d (host) > ");
    return (cparser_submode_enter(context->parser, NULL, prompt));
}

cparser_result_t
cparser_cmd_host_quit (cparser_context_t *context)
{
    assert(context && context->parser);
    return cparser_submode_exit(context->parser);
}

cparser_result_t
cparser_cmd_host_cmd (cparser_context_t *context, char **cmd_ptr)
{
    system(*cmd_ptr);
    return CPARSER_OK;
}
