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
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <cparser.h>
#include <cparser_tree.h>
#include <an_logger_linux.h>

cparser_result_t 
cparser_cmd_configure_debug_log_console (cparser_context_t *context)
{
    an_log_stdout_set();
    return (CPARSER_OK);
}

cparser_result_t 
cparser_cmd_configure_debug_log_file_logfile (cparser_context_t *context,
                                        char **logfile_ptr)
{
    an_log_file_set(*logfile_ptr);
    return (CPARSER_OK);
}
