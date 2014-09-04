/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __STRIE_H_
#define __STRIE_H_ 

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <regex.h>

/**
 * Max command length
 */
#define MAXLINE 256

#ifndef MIN
#define MIN(A,B) ((A) < (B) ? (A) : (B))
#endif

/**
 * Callback function type
 */
typedef void (*fp) (bool, int, char **);
typedef fp cbk_t;

#define INVALID_LIDX          127
#define MAX_PRINTABLE_ASCII   126
#define BEGIN_PRINTABLE_ASCII  33

#define MAX_CHARS  (MAX_PRINTABLE_ASCII - BEGIN_PRINTABLE_ASCII + 1)

/**
 * Convert a character to its link index
 */
#define CHAR2LIDX(C)  (C - BEGIN_PRINTABLE_ASCII)

/**
 * Convert a link index to character
 */
#define LIDX2CHAR(L)  (L + BEGIN_PRINTABLE_ASCII)

#define MAX_CLI_ARGS  10  /* restrict to 10 arguments per CLI */

typedef struct dyn_opt_ {
    char *cmd_prefix;    /**< The part of the command before OPT */
    char *opt_str;       /**< The option keyword */
    char *val;           /**< The value associated with the keyword
                              (optional) */
    char *regex_prefix;  /**< true if we had some user input points 
                              before OPT - this is a regex, and has to be
                              compiled before use (we cant compile and store) */
    char *base_prefix;   /**< top most (or smalles-leftmost) prefix which also
                              has a dynamic option node */
} dyn_opts_t ;

#define OPT_MARKER       "<OPT>"
#define OPT_MARKER_LEN   5
typedef struct trie_ {
    struct trie_ *link[MAX_CHARS]; /**< The links corresponsing to input 
                                        alphabet */
    bool eow;       /**< End Of Word node */
    char *v;        /**< 'value' - nothing but the user given command - as is */
    fp f;           /**< Func invoked on reaching terminal node */
    bool no;        /**< Does this command have a 'no' form ?*/
    char *h;        /**< Help string */
    /* more data for autocomplete */
    short linkcnt;  /**< Link count (number of outgoing links - the fan out) */
    short flidx;    /**< when linkcnt is 1, this holds the only link's index */
    bool sp;        /**< word boundry node (has space) */
    bool uinp;      /**< read user input at this node */
    dyn_opts_t *dyn_opts;
} trie;

bool  strie_what_next (trie *t,char *p);
void  strie_insert (trie *t, const char *k, const char *v, const char *h,
                   fp f, bool no);
void  strie_insert_opts (trie *tri, const char *k, const char *v, const char *h, 
                         fp f, bool no, char **opts, char **vals, bool no_eol);
void  strie_delete (trie *t, const char *k, trie *p, int i, int d); 
trie *strie_newnode ();
trie *strie_find_pfxnod (trie *t,char *key, bool *inp_gobbled);
trie *strie_search (trie *t, const char *key);
bool  strie_find_completion (trie *t, char *p, char *r, bool *read_inp);
bool  strie_find_exact (trie *t, char *k);

/* Generic Trie routines - used in rc/var implementation */
bool  strie_get_val (trie *t, char *c, char **v);
void  strie_walk (trie *t, void (*fp)(trie *, void *), void *);
char *strie_get_node_val (trie *t);
char *strie_get_node_help (trie *t);
void  strie_destroy (trie *t);

#endif 
