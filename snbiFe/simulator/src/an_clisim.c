/*
 * Vijay Anand R <vanandr@cisco.com>
 *
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <cparser.h>
#include <cparser_tree.h>
#include "../impl/an_conf_linux.h"

extern int an_debug_map[];

int
main (int argc, char *argv[])
{
    cparser_t parser;
    char *config_file = NULL;
    int ch, debug = 0;
    int interactive = 0;

    memset(&parser, 0, sizeof(parser));

    if (argc < 2) {
        printf("\nInvalid options passed use -h to know the right command\n");
        return 1;
    }



    while (-1 != (ch = getopt(argc, argv, "ihd"))) {
        switch (ch) {
            case 'i':
                interactive = 1;
                break;
            case 'd':
                debug  = 1;
                break;
            case 'h':
                printf("\n-h \tDisplay the help and exit");
                printf("\n-i \tEnter into interactive mode");
                printf("\n-d \tEnable parser debug mode");
                printf("\n\n");
                return 0;
                break;
        }
    }

    parser.cfg.root = &cparser_root;
    parser.cfg.ch_complete = '\t';
    /*
     * Instead of making sure the terminal setting of the target and
     * the host are the same. ch_erase and ch_del both are treated
     * as backspace.
     */
    parser.cfg.ch_erase = '\b';
    parser.cfg.ch_del = 127;
    parser.cfg.ch_help = '?';
    parser.cfg.flags = (debug ? CPARSER_FLAGS_DEBUG : 0);
    strcpy(parser.cfg.prompt, "clisim > ");
    parser.cfg.fd = STDOUT_FILENO;
    cparser_io_config(&parser);

    if (!an_system_init_linux()) {
        return -1;
    }


    if (CPARSER_OK != cparser_init(&parser.cfg, &parser)) {
        printf("Fail to initialize parser.\n");
        return -1;
    }
    if (interactive) {
        if (config_file) {
            (void)cparser_load_cmd(&parser, config_file);
        }
        cparser_run(&parser);
    }
    return 0;
}
