/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __LIBCLI_H
#define __LIBCLI_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

#include "termio.h"
#include "strie.h"

/**
 * Flags for the cli_do_cmd_general
 * Log the command executed, if command logging is enabled
 */
#define CLI_CMD_LOG             0x01
/**
 * Display alias expansion, if the command were an alias and the 
 * rc file read/alias were enabled 
 */
#define CLI_CMD_ECHO_EXPANDED   0x02

/**
 * Periodic callback function signature 
 */
typedef void (*periodic_cbk_t) (void);

/* read from users home dir */
#define CLI_RC_DEFAULT  ".clirc" 

/* write command logs to the current dir */
#define CLI_CMD_LOG_FILE "./clicmds.log"

typedef struct cli_set_ {
    trie  *t;                /**< Trie root node */
    int    num_clis;         /**< Number of CLIs inserted into the trie */
    char  *prompt;           /**< Prompt (given in \c cli_init) */
    int    plen;             /**< length of \c prompt */
    struct cli_set_ *next;   /**< Link to submode */
    periodic_cbk_t periodic; /**< Periodic function pointer */
} cli_set_t;

typedef struct cli_optval_ {
    char *opt;               /**< Option string (key) */
    int   val;               /**< Value associated with the above key */
} cli_optval_t;

cli_set_t* cli_init(const char * prompt, const char * exit_cmd, cbk_t exit_fp);
bool cli_insert (cli_set_t *s, const char *command, const char *help_str,
                 cbk_t fp, bool no_form);
bool cli_insert_hidden (cli_set_t *s, const char *command, cbk_t fp, 
                        bool no_form);
bool cli_insert_opts (cli_set_t *s, const char *c, const char *h,
                      cbk_t fp, bool no, char **opts);
bool cli_insert_opts_noeol (cli_set_t *s, const char *c, const char *h,
                            cbk_t fp, bool no, char **opts);
bool cli_insert_optval (cli_set_t *s, const char *c, const char *h,
                        cbk_t fp, bool no, cli_optval_t *optval);
void cli_delete (cli_set_t *s, const char *command);
void cli_delete_opts (cli_set_t *s, const char *c, char **opts);
void cli_loop (cli_set_t *s);
void cli_cmd_file (cli_set_t *s, char *filename);
void cli_cmd_stdin (cli_set_t *s);
void cli_handle_args (cli_set_t *cs, int argc,char **argv);
void cli_read_rc (char *filename);
void cli_log_cmds (char *filename);
bool cli_do_cmd (cli_set_t *s, char *c);
bool cli_do_cmd_general (cli_set_t *s, char *c, unsigned short flags);
void cli_do_help (cli_set_t *s, char *pfx);
void cli_set_periodic (cli_set_t *cs, periodic_cbk_t pfp); /* Only when 
                                                              cli_loop used */
const char* cli_get_version (void);

/* submode functions */
void cli_push_mode (cli_set_t *parent, cli_set_t *child);
void cli_destroy_set (cli_set_t *s);
void cli_pop_mode (cli_set_t *parent);

#endif 
