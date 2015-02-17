/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "flread.h"

/**
 * Read lines from file, 'line' alloc'd by \c getline 
 *
 * Opaque data is passed as is to the handler func
 *
 * @param[in] fname File name to read
 * @param[in] hdlr  The function pointer which will be called with the opaque
 *                  data \c opq for each nonempty line
 * @param[in] opq  Opaque data to pass on to \c hdlr 
 */
int flread (char *fname, flread_cbk hdlr, void *opq)
{
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(fname,"r");
    if (fp == NULL) {
        return (0);
    }
    while ((read = getline(&line, &len, fp)) != -1) {
        line[read - 1] = '\0'; /* Should be 0x0A in case of DOS/Unix */
        if (line[read - 2] == 0x0D) { /* DOS */
            line[read - 2] = '\0';
        }
        if (strlen(line)) {
            hdlr(line, opq);
        }
    }
    if (line) {
        free(line);
    }
    return (1);
}

/**
 * Read lines from stdin
 *
 * Opaque data is passed as is to the handler func
 *
 * @param[in] hdlr  The function pointer which will be called with the opaque
 *                  data \c opq for each nonempty line
 * @param[in] opq  Opaque data to pass on to \c hdlr 
 */
int stdin_read (flread_cbk hdlr, void *opq)
{
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, stdin)) != -1) {
        line[read - 1] = '\0';
        if (strlen(line)) {
            hdlr(line, opq);
        }
    }
    if (line) {
        free(line);
    }
    return (1);
}
