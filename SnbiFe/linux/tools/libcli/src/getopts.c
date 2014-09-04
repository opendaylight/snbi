/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include "libcli.h"
#include "automore.h"
#define PRINT_USAGE \
        printf ("Usage: %s [-h] [-f <file>]\n", argv[0])

/** 
 * Handle command line args 
 *
 * From main, pass the argc, argv as is, handles input from file/stdin
 *
 * @param[in] cs    The CLI set (initialised)
 * @param[in] argc  argc from \c main()
 * @param[in] argv  argv from \c main()
 * @note Call this after all the \c cli_insert s and before the \c cli_loop
 */
void cli_handle_args (cli_set_t *cs, int argc, char **argv)
{
    int c, opts = 0;
    bool help = false;

    opterr = 0;
    while ((c = getopt (argc, argv, "hf:")) != -1) {
        switch (c) {
            case 'f':
                if (optarg) {
                    cli_cmd_file(cs, optarg);
                    exit(0); /* see explanation after cli_cmd_stdin */ 
                }
                break;
            case 'h':
                help = true;
                opts++;
                break;
            case '?':
                if  (optopt == 'f') {
                    fprintf (stderr, "Option -%c requires an argument (%s).\n", 
                             optopt, (optopt =='f') ? "filename": "");
                } else if (isprint (optopt)) {
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                } else {
                    fprintf (stderr, "Unknown option character `\\x%x'.\n",
                             optopt);
                }
                exit(1);
            default:
                printf("Unknown : abort\n");
                abort ();
        }
    }

    if (help) {
        PRINT_USAGE;
        printf ("       -h : This help text\n"
                "       -f : File to read commands from\n" 
                "            (1 per line)\n\n"
                " Default is to run in interactive mode\n"
                " type 'help' in the command prompt for more\n");
        exit(0);
    }

    if (!opts && !isatty(STDIN_FILENO)) {
        cli_automore_disable();
        cli_cmd_stdin(cs);
        exit(0); /* doesnt matter whether last command was 'exit/quit', just end
                    because we are in non interactive mode */
    }
}

