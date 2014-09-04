/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "strie.h"
#include "automore.h"

/**
 * @file
 *
 * An uncompressed Trie, with printable ASCII as input (33 ... 126)
 * Knows where a word ends, where user input can be read
 * 94 links per node is a bit bulky but should be faster than string compare
 * at each stage of completion!, at least, that is what I think!
 *
 */

/**
 * @defgroup Trie Trie module 
 * @{
 */
void cli_lib_help (void);
static char *args[MAX_CLI_ARGS];
static int nargs;

/**
 * Initialise node members
 * @param[in]  t  Trie node to initialise
 */
static void strie_init (trie *t)
{
    t->eow = false; /* Ideally calloc must take care of all these ... */
    t->v = NULL;
    t->h = NULL;
    t->f = NULL;
    t->sp = false;
    t->uinp = false;
    t->linkcnt = 0;
    t->flidx = INVALID_LIDX;
    t->dyn_opts = NULL;
}

/* Forward declaration */
static void strie_do_dfs (trie*, bool);

/* 
 * These are for the dynamic keyword options, I hate using globals, but 
 * until I come up with a better solution, this is what we have!
 */
static char *g_cmd_pfx = NULL;
static bool g_cmd_displayed = false;
static char g_displayed_pfx[MAXLINE];

/**
 * Display all possible completions from node \c t
 *
 * @param[in]  t   The trie node to start traversal from
 * @param[in]  no  Whether the current command has a 'no' prefix
 * @param[in]  p   The command (or prefix) entered so far
 */
static void strie_display_possibles (trie *t, bool no, char *p) 
{
    cli_automore_begin();
    putchar('\a');
    g_cmd_displayed = false;
    g_cmd_pfx = p; /* just to avoid passing down the recursive calls */
    strie_do_dfs(t, no);
    g_cmd_pfx = NULL;
}

/**
 * Find a exact matching key in the trie
 *
 * @param[in]  t  Trie node to begin search from
 * @param[in]  k  The Key - or trimmed command string
 *
 * @note      Difference between this and the strie_find_pfxnod
 *            function is just \c eow handling
 *
 * @return the trie node found if successful, NULL otherwise
 */
trie* strie_search (trie *t, const char *k)
{
    int d, n = strlen(k);

    for (d = 0; (d < n) && t ; d++) {
        if (k[d] == ' ') {
            continue;
        }
        t = t->link[CHAR2LIDX(k[d])];
        if (t && t->uinp) {
            d += 2;
            if (k[d] && t->link[CHAR2LIDX(k[d])] ) {
                d --;  /* try 2 see if we can go further, if we cant, back */
                continue;
            }
            while (k[d] && k[d] != ' ') {
                d++; /* skip a word  */
            }
        }
    }  
    if (t && t->eow) {
        return (t);
    }

    return (NULL);
}

/**
 * Find a node which matches the prefix. 
 *
 * This will be the longest prefix from the start
 * which can contain user input words as well 
 *
 * @param[in]  t   Trie node to begin search from
 * @param[in]  pfx The prefix (on command line) to search for
 * @param[out] gobbled  True if we skipped over user input word
 *
 * @return the trie node found if successful, NULL otherwise
 */
trie* strie_find_pfxnod (trie *t, char *pfx, bool *gobbled)
{
    int d, n = strlen(pfx);

    for (d = 0; t && pfx[d] && (d < n); d++) {
        *gobbled = false;
        if (pfx[d] == ' ') {
            continue;
        }
        t = t->link[CHAR2LIDX(pfx[d])];
        if (t && t->uinp) {
            d += 2; /* skip the curr char and a sp (assume 1 sp) */
            /*
             * At this point, if we can try to lookahead, we must 
             * i.e, longest match as a command first, and 
             * then try to read user input 
             */
            if (pfx[d] && islower(pfx[d]) && t->link[CHAR2LIDX(pfx[d])] ) {
                d --; 
                continue;
            }
            while (pfx[d] && pfx[d] != ' ') { /* skip a word  */
                d++; 
                *gobbled = true;
            }
        }
    }
    if (t) {
      return (t);
    }
    
    return (NULL);
}

/**
 * Allocate and initialise a new node 
 *
 * @return Node pointer on success, NULL on failure
 */
trie* strie_newnode()
{
    trie *t = NULL;

    t = calloc(1, sizeof(trie));
    if (!t) {
        fprintf (stderr,"CLI: Memory Exhausted\n");
        abort();
    }
    strie_init(t);

    return (t);
}

/**
 * Recursively insert a node into the trie
 *
 * @param[in]  t   Trie node 
 * @param[in]  k   Key (trimmed command string)
 * @param[in]  d   Depth (the character position in recursive calls)
 *
 * @return Final node inserted if successful
 */
static trie* strie_insert_r (trie *t, const char *k,  int d) 
{
    if ( !k || '\0' == k[d]) {
        if (t->v) {
            printf ("Duplicate Entry [%s]!\n", t->v);
            return (NULL);
        }
        t->eow = true;
        return (t);
    } else {
        trie  *tmp = NULL;
        int    j;

        if (k[d] == ' ') { 
            t->sp = true;
            d++; /* mov to next char*/
        } 
        j = CHAR2LIDX(k[d]);
        if (!t->link[j]) {
            tmp = strie_newnode();
            if (t->dyn_opts) {
                /* 
                 * Any new command which may not have a dyn option, but 
                 * has the same prefix as previously inserted command 
                 * with dyn option, shall inherit the dyn option as well.
                 */
                tmp->dyn_opts = calloc (1, sizeof(dyn_opts_t));
                assert(tmp->dyn_opts);
                tmp->dyn_opts->opt_str = strdup(t->dyn_opts->opt_str);    
                tmp->dyn_opts->cmd_prefix = strdup(t->dyn_opts->cmd_prefix);
                if (t->dyn_opts->regex_prefix) {
                    tmp->dyn_opts->regex_prefix = 
                                        strdup(t->dyn_opts->regex_prefix);
                }
            }
            t->link[j] = tmp;
            /* for autocomplete */
            t->linkcnt ++;
            if (t->linkcnt == 1) {
                t->flidx = j;
            }
        }
        if (k[d + 1] == ' ' && k[d + 2] == '@') {
            if (tmp) {
                tmp->uinp = true; 
            } else {
                (t->link[j])->uinp = true; /* if the node were already 
                                              created - just mark it */
            }
            d += 2;
            if (k[d] == ' ') {
                d++; 
            }
        } 
        return strie_insert_r(t->link[j], k, d + 1);
    }
}

/** 
 * Insert a command into the trie
 * Calls the \c strie_insert_r to recursively do the insertion
 *
 * @param[in]   v        The command string - untrimmed (as given by the user) 
 *                       This is what is used in the display
 * @param[in]   tri      The Trie root node
 * @param[in]   k        Key - the trimmed command string
 * @param[in]   h        help string
 * @param[in]   f        The callback function pointer for command \c k
 * @param[in]   no       If a 'no' form of this command is needed
 *
 * @note we make a copy of the un-trimmed command as well as the help
 */
void strie_insert (trie *tri, const char *k, const char *v, const char *h, 
                   fp f, bool no)
{
    trie *t = strie_insert_r(tri, k, 0);

    if (t) {
        if (v && h) { /* Not a hidden command */
            t->v = strdup(v); 
            assert(t->v);
            t->h = strdup(h);
            assert(t->h);
        }
        t->f = f;
        t->no = no;
    }
}

/**
 * Given a prefix \c p containing some user inputs (marked `@')
 * Convert it into a regex, which can be matched when the command
 * is entered by the user.
 *
 * @verbatim
 * i.e, a command like:
 *   get <some> value
 * gets converted to:
 *   get .* value
 * @endverbatim
 *
 * @param[in]  p  Prefix pointer
 * @param[out] d  Destination pointer (memory to be allocated by caller)
 *
 * @return true if we found some `@' chars, and replaced them
 */
static bool build_regex (char *p, char *d)
{
    char *t;
    bool ret = false;

    while ((t = strchr(p, '@'))) {
        ret = true;
        strncat(d, p, t-p);
        p = t + 1;
        strcat(d, ".*");
    }
    if (p) {
        strcat(d, p); 
    }

    return (ret);
}

/**
 * Find and return the first (leftmost/topmost) dynamic options
 * node in the given command \c k
 *
 * @param[in] t Trie root node
 * @param[in] k The key - command string
 *
 * @return first dynamic node if found, NULL otherwise
 */
static trie* strie_find_first_dyn_node (trie *t, const char *k)
{
    int d, n = strlen(k);

    for (d = 0; (d < n) && t ; d++) {
        if (k[d] == ' ') {
            continue;
        }
        t = t->link[CHAR2LIDX(k[d])];
        if (t && t->dyn_opts) {
            return (t);
        }
    }  

    return (NULL);
}

/**
 * Get the shortest-leftmost prefix string which also has a
 * dynamic options node
 *
 * @param[in]  t    Trie root node 
 * @param[in]  in   Input command 
 * @param[out] out  Output prefix if found
 *
 * @note given a input like:
 *     hello world #
 * If there is also a node like:
 *     hello #
 * return "hello" in \c out
 *
 * @return \c true if a prefix was found, \c false otherwise 
 */
static bool strie_get_dyn_pfx (trie *t, const char *in, char *out)
{
    trie *tmp = NULL;
    tmp = strie_find_first_dyn_node(t, in);
    if (tmp && tmp->dyn_opts) {
        strcpy(out, tmp->dyn_opts->cmd_prefix);
        return (true);
    }
    return (false);
}

static bool insert_half (trie *tri, const char *k, const char *v,
                         const char *h, fp f, bool no, 
                         const char *opt, 
                         const char *val, 
                         const char *opt_pfx, 
                         const char *re_pfx,
                         bool at_end,
                         bool no_eol)
{
    trie *t = NULL;
    char dpfx[MAXLINE] = {0};

    t = strie_insert_r(tri, k, 0);
    if (!t) {
        return (false); 
    }
    t->v = strdup(v); 
    assert(t->v);
    t->f = f;
    t->no = no;
    t->h = strdup(h);
    assert(t->h);
    t->dyn_opts = calloc (1, sizeof(dyn_opts_t));
    assert(t->dyn_opts);
    t->dyn_opts->opt_str = strdup(opt);   /* this is used by pluck_args */
    t->dyn_opts->cmd_prefix = strdup(opt_pfx); /* if we have regex pfx, this
                                                is useless, lets cleanup l8r */
    assert(t->dyn_opts->opt_str && t->dyn_opts->cmd_prefix);
    /*
     * If there is a shorter prefix for this options command, which also
     * has a dynamic option, keep track of it - we'll need it later
     */
    if (strie_get_dyn_pfx(tri, opt_pfx, dpfx) && 
                (strlen(dpfx) < strlen(opt_pfx))) {
        t->dyn_opts->base_prefix = strdup(dpfx);
        assert(t->dyn_opts->base_prefix);
    }
    if (val) {
        t->dyn_opts->val = strdup(val); 
        assert(t->dyn_opts->val);
    }

    if (re_pfx) {
        /*
         * If the prefix had a user input, then, we cant
         * do a strcmp, at runtime, we can only do a 
         * regex match
         */
        t->dyn_opts->regex_prefix = strdup(re_pfx);
        assert(t->dyn_opts->regex_prefix);
    }
    if (!at_end) {
        t->eow = false; /* Note: this is to say that the first part 
                           which we inserted is not really a complete 
                           command. If not at end, we are assuimg that 
                           this is a second level 
                           option */
    }
    if (no_eol) { 
        /* 
         * If user explicitly says this is not the command's end, 
         * so shall it be. 
         */
        t->eow = false;
    }

    return (true);
}

/** 
 * Insert a command with option appended, into the trie
 *
 * Calls the \c strie_insert_r to recursively do the insertion
 *
 * Each occurence of the sub-string "<OPT>" in the command \c k
 * is replaced with one string from options array, and inserted into the Trie.
 *
 * @param[in]   v        The command string - untrimmed (as given by the user) 
 *                       This is what is used in the display
 * @param[in]   tri      The Trie root node
 * @param[in]   k        Key - the trimmed command string
 * @param[in]   h        help string
 * @param[in]   f        The callback function pointer for command \c k
 * @param[in]   no       If a 'no' form of this command is needed
 * @param[in]   opts     Array of options (C-strings) terminated by NULL  
 *                       (these are words [or keys])
 * @param[in]   vals     Array of values (C-strings) terminated by NULL  
 *                       (these are values for each of the opts keys)
 * @param[in]   no_eol   true if this is a full command, if not, EOL is 
 *                       not inserted, and this command is treated as part of 
 *                       a command. 
 *
 * @note similar to \c strie_insert, but inserts multiple commands into the
 *       Trie (as many as the number of elements in the \c opts array)
 */
void strie_insert_opts (trie *tri, const char *k, const char *v, const char *h, 
                        fp f, bool no, char **opts, char **vals, bool no_eol)
{
    char tmp[MAXLINE] = {0}, till_opt[MAXLINE] = {0};
    char pfx[MAXLINE] = {0}, hlp[MAXLINE] = {0};
    char full[MAXLINE] = {0}, re_pfx[MAXLINE] = {0};
    bool at_end = false, re_built = false;
    char *p = strchr(k, '#'); /* <OPT> will be substituted with `#' by now */

    /*
     * On giving a command like:
     *          protocol name <OPT> sub-opt <uinp>
     * If <OPT> were not in the end of the command, then:
     *          Break it up into:
     *                  protocol name <OPT-substituted>
     *          insert it, and then insert:
     *                  protocol name <OPT-substituted> sub-opt <uinp>
     *          We assume, we are given only 1 <OPT>
     * else, if <OPT> were at then end, just 1 insert
     */
    if (!p) {
        return;
    }
    strncpy(till_opt, k, p - k); /* no need for NUL term */
    at_end = (*(p+1) == '\0') ?  true : false;
    if (!at_end) {
        strncpy(full, k, p - k);
        strcat(full, "%s");
        strcat(full, p + 1);
    }

    /* Get the prefix of the command (before #) */
    strncpy(pfx, k, p - k - 1); 

    /* 
     * If the part of the command before OPT had some user input points,
     * then build regex prefix
     */
    re_built = build_regex(pfx, re_pfx);

    while (*opts) {
        snprintf(tmp, MAXLINE, "%s%s", till_opt, *opts); 
        /* 
         * strie_insert_r doesn't know much about the dynamic options 
         * (except to allow inheritence), and as usual it returns the last 
         * node inserted. But, for this case we want the last node to be the 
         * options node. Hence we first have to insert the part of the command 
         * till the options, and insert the rest later 
         *
         * Crafting the displayed command (t->v) is a li'l 
         * cryptic in this case, because, we can have "<OPT>"
         * and <userinput>s (@)
         */
        hlp[0] = '\0';
        p = strstr(v, OPT_MARKER);
        strncpy(hlp, v, p - v);
        hlp[p - v] = '\0';
        strcpy(pfx, hlp); 
        strcat(hlp, *opts);
        insert_half(tri, tmp, hlp, h, f, no, *opts, vals ? *vals : NULL, 
                    pfx, re_built ? re_pfx : NULL, at_end, no_eol);
        if (!at_end) {
            /* we have to insert one more */
            strcat(hlp, p + OPT_MARKER_LEN);
            snprintf(tmp, MAXLINE, full, *opts);
            /*
             * simply add a dyn opts node at the end, so that the
             * auto compress thing works at top level 
             */
            insert_half(tri, tmp, hlp, h, f, no, *opts, vals ? *vals : NULL, 
                        pfx, re_built ? re_pfx : NULL, 
                        true,   /* at_end is true now */
                        no_eol); 
        }
        opts++;
        vals ? vals++ : 0;
    }
}

static void strie_free_node (trie *t, int i, trie *p)
{
    if (t && !t->linkcnt) {
        if (p) {
            /* set values in parent appropriately */
            p->linkcnt --;
            p->link[i] = NULL;
        }
        if (t->dyn_opts) {
            free(t->dyn_opts->opt_str);
            free(t->dyn_opts->cmd_prefix);
            if (t->dyn_opts->regex_prefix) {
                free(t->dyn_opts->regex_prefix);
            }
        }
        if (t->v) {
            free(t->v);
        }
        free(t);
    }
}

/**
 * Delete a command \c k from the Trie
 *
 * @param[in] t is the node we are operating on
 * @param[in] k Key - the trimmed command string
 * @param[in] p \c t's parent
 * @param[in] i the index of the link we took to reach \c t from \c p
 * @param[in] d the depth we are at 
 */
void strie_delete (trie *t, const char *k, trie *p, int i, int d)
{
    if (k[d] && (t->linkcnt != 0)) {
        int j;

        if (k[d] == ' ') {
            d++;
        }
        j = CHAR2LIDX(k[d]);
        strie_delete(t->link[j], k, t, j, d+1);
    }
    strie_free_node(t, i, p);
}

/* 
 * Do a DFS and destroy  all nodes of trie \c t
 *
 * @param[in] t Trie root node
 * @param[in] i The index of \c p where \c t is attached, i.e, 
 *              \c p->link[i] is \c t
 * @param[in] p Parent of \c t
 */
static void strie_destroy_r (trie *t, int i, trie *p)
{
    for (i = 0; i < MAX_CHARS; i++) {
        if (t->link[i]) {
            strie_destroy_r(t->link[i], i, t);
        }
    }
    strie_free_node(t, i, p);
}

/**
 * Destroy entire trie, given the root node 
 *
 * @param[in] t Trie root node (of any mode)
 */
void strie_destroy (trie *t)
{
    if (!t) {
        return;
    }
    strie_destroy_r(t, 0, NULL);
}

/**
 * Create a key by stripping off spaces, also validate chars
 * 
 * @param[in]   c   Command string - by the user
 * @param[out]  k   Trimmed command string
 *
 * @param[out]  no  True if the command begins with a 'no'
 * @param[out]  help  True if the command begins with 'help'
 *
 * @note   \c k to be allocated by the caller
 *
 */
static bool strie_mk_key (char *c, char *k, bool *no, bool *help)
{
    char pc = 0;

    while (isspace(*c)) {
        c++;
    }

    if (help) {
        *help = false;
    }

    *no = false;
    if (strncmp(c, "no", 2) == 0) {
        *no = true;
        c += 2;
    } else if (strncmp(c, "help", 4) == 0) {
        if (help) {
            *help = true;
        }
        c += 4;
    }

    while (*c) {
        if (*c == ' ') {
            if (pc != ' ') {
                *k++ = ' ';
            }
        } else {
            *k++ = *c;
        }
        pc = *c;
        c++;
    }

    return (true);
}

/**
 * Display the full command on '?'
 *
 * Called from the DFS walker
 *
 * @param[in]  t     Trie terminal node
 * @param[in]  no    Will be true if trying to complete 'no' form of a cmd
 *                   (i.e user started with a 'no' )
 */
static void strie_disp_cmd (trie *t, bool no)
{
    if (no) {
        if (t->no) {
            cli_automore_print("\tno %s\n", t->v);
        }
        return;
    }
    if (t->dyn_opts) {
        regex_t re;
        /*
         * If this were a node with a regex prefix, do a regex 
         * prefix match (we cannot keep the compiled regex in 
         * t->dyn_opts because, there are no clone functions
         * for regex_t, and we may have the same node cloned in 
         * multiple places, so when we do a regfree, will crash)
         */
        if (t->dyn_opts->regex_prefix) {
            if (regcomp(&re, t->dyn_opts->regex_prefix, 
                        REG_EXTENDED|REG_NOSUB) != 0) {
                printf("\nstrie: regex compilation failed for [%s]\n",
                       t->dyn_opts->regex_prefix);
                return;
            }
            if (regexec(&re, g_cmd_pfx, (size_t)0, NULL, 0) == 0) {
                cli_automore_print("\t%s %s\n", t->no ? "[no]": "    ", t->v);
                return;
            }
            regfree(&re);
        }
        if (0 == strncmp(g_cmd_pfx, t->dyn_opts->cmd_prefix, 
                         strlen(t->dyn_opts->cmd_prefix))) {
            /* If we have come till the options point, only then display them */
            cli_automore_print("\t%s %s\n", t->no ? "[no]": "    ", t->v);
        } else {
            /* Display only at level 0, in lower levels, dont display */
            int n = strlen(g_cmd_pfx);

            if (0 != strncmp(g_displayed_pfx, t->dyn_opts->cmd_prefix, 
                        strlen(g_displayed_pfx))) {
                g_cmd_displayed = false;
            }
            if (!g_cmd_displayed) {
                /*
                 * Spl case, we are at top level, but the recursive calls
                 * (dfs) has brought us too down deep, and we want to see
                 * if there is a upper level dyn opt which we can displayed
                 */
                if (!n && t->dyn_opts->base_prefix) {
                    cli_automore_print("\t%s %s ...\n", t->no ? "[no]": "    ", 
                            t->dyn_opts->base_prefix);
                    g_cmd_displayed = true;
                    strcpy(g_displayed_pfx, t->dyn_opts->base_prefix);
                    return;
                }
                /* 
                 * We shall print the compressed form once only, and not
                 * for reach leaf of the Trie 
                 */
                cli_automore_print("\t%s %s ...\n", t->no ? "[no]": "    ", 
                        t->dyn_opts->cmd_prefix);
                g_cmd_displayed = true;
                strcpy(g_displayed_pfx, t->dyn_opts->cmd_prefix);
            }
        }
    } else {
        /* normal (non OPTions command) */
        if (t->v) { /* Not a hidden command */
            cli_automore_print("\t%s %s\n", t->no ? "[no]": "    ", t->v);
        }
    }
}

/**
 * Do a DFS from the given node and display matches at \c eow
 *
 * @param[in]  t     Trie node to start recursing down
 * @param[in]  no    Will be true if trying to complete 'no' form of a cmd
 *                   (i.e user started with a 'no' )
 */
static void strie_do_dfs (trie *t, bool no)
{
    int i;

    for (i = 0; i < MAX_CHARS; i++) {
        if (t->link[i]) {
            strie_do_dfs(t->link[i], no);
        }
    }
    if (t && t->eow) {
        strie_disp_cmd(t, no);
    }
}

/**
 * Generic version of \c strie_do_dfs
 *  
 * Walk the trie \c t, and for each node, call \c fp
 *
 * @param[in]  t     Trie root node
 * @param[in]  fp    Pointer of the function to be called
 * @param[in]  data  Pointer to user data (opaque)
 */
void strie_walk (trie *t, void (*fp)(trie *, void *), void *data)
{
    int i;

    for (i = 0; i < MAX_CHARS; i++) {
        if (t->link[i]) {
            strie_walk(t->link[i], fp, data);
        }
    }
    if (t && t->eow) {
        fp(t, data);
    }
}

/**
 * Get value field from node
 *
 * @param[in] t Trie node
 * @return value field \c v of the node
 */
char *strie_get_node_val (trie *t)
{
    return (t && t->v) ? t->v : "";
}

/**
 * Get help field from node 
 *
 * @param[in] t Trie node
 * @return value field \c h of the node
 */
char *strie_get_node_help (trie *t)
{
    return (t && t->h) ? t->h : "";
}

/**
 * Initialise the command args array (which will be passed to the
 * callback functions on command completion)
 */
static void args_init ()
{
    int i;

    for (i = 0; i < MAX_CLI_ARGS; i++) {
        if (args[i]) {
            free(args[i]);
            args[i] = NULL;
        }
    }
    nargs = 0;
}

/**
 * Add an arg to the \c args list by clipping from given positions in 
 * the completed command.
 *
 * @param[in]  cli The current command line
 * @param[in]  b   The start position to clip
 * @param[in]  e   The end position
 */
static void args_add_pos (char *cli, int b, int e)
{
    char * p = NULL;

    if ((e - b) > 0) {
        if (cli[b] == cli[e-1] && (cli[b] == '"' || cli[b] == '\'')) {
            b++, e--;
        }
        args[nargs] = calloc(1, e - b + 1);
        if (!args[nargs]) {
            fprintf(stderr, "CLI: Failed to allocate args\n");
            return;
        }
        strncpy(args[nargs], cli + b, e - b);
        args[nargs][e - b] = '\0'; /* alas strncpy never does this! */
        while ((p = strchr(args[nargs], CHR_PILCROW))) {
            *p = CHR_SPACE; 
        }
        nargs++;
    }
}

/**
 * Add an arg to the \c args list 
 *
 * @param[in]  s   The arg string
 */
static void args_add_str (char *s)
{
    if (s) {
        args[nargs] = strdup(s);
        assert(args[nargs]);
        nargs++;
    }
}

/**
 * Given a command string and a position between some word, 
 * return the whole word in \c word
 *
 * This is required only in case of a command having multiple
 * dynamic optin strings, in which case, when we are plucking
 * the words to build arg list, we will not know which ones
 * to pick, so this helps make the decision
 *
 * @param[in]  c    The command string
 * @param[in]  pos  A position between some word
 * @param[out] word The whole word within which \c pos was pointing to
 */
void get_cur_word (const char *c, int pos, char **word)
{
    int e, b;

    while (c[pos] != ' ') {
        pos--; /* go back till we find a word boundary */
    }
    pos++;
    b = pos;
    while (c[pos] && c[pos] != ' ') {
        pos++; /* move till the end of this word */
    }
    e = pos;
    *word = calloc(1, e - b + 1);
    if (!*word) {
        fprintf(stderr, "CLI: Failed to allocate dyn arg\n");
        return;
    }
    strncpy(*word, c + b, e - b);
    (*word)[e - b] = '\0'; 
}

/**
 * Pluck all the user entered words from the current command line
 *
 * Walk through the Trie and make out where we have user-input markers
 * and in those position, clip a word and add it to the \c args list
 *
 * @param[in] t  The trie root node
 * @param[in] c  The current command line
 */
static void pluck_args (trie *t, char *c)
{
    int d, n = strlen(c);
    int arg_begin, arg_end;
    char *word;

    args_init();
    for (d = 0; t && c[d] && (d < n); d++) {
        if (c[d] == ' ') { 
            continue;
        }
        t = t->link[CHAR2LIDX(c[d])];
        /* If this were a node with dynamic options, add it to args */
        if (t && t->dyn_opts) {
            /* 
             * Note: this must come before user inp check (the next if())
             * assuming, all <OPT>s come before user input
             */
            get_cur_word(c, d, &word);
            if (strcmp(word, t->dyn_opts->opt_str) == 0) {
                if (t->dyn_opts->val) {
                    args_add_str(t->dyn_opts->val);
                } else {
                    args_add_str(t->dyn_opts->opt_str);
                }
            }
            free(word);
        }
        if (t && t->uinp) {
            d += 2 ;
            if (c[d] && t->link[CHAR2LIDX(c[d])] ) {
                d --;  /* try 2 see if we can go further, if we cant, back */
                continue;
            }
            arg_begin = d;
            while (c[d] && c[d] != ' ') {
                d++; /* skip a word  */
            }
            arg_end = d;
            args_add_pos(c, arg_begin, arg_end);
        }
    }  
}

/**
 * Get the value \c v for key \c c 
 *
 * @param[in]  t  The trie root node
 * @param[in]  c  The current command 
 * @param[out] v  The value assigned for the command \c c
 */
bool strie_get_val (trie *t, char *c, char **v)
{
    trie *n = NULL;
    char k[MAXLINE] = {0};
    bool ret = false;
    bool no, help;
    
    if (!c || !v) {
        return (ret);
    }
    if (!strie_mk_key(c, k, &no, &help)) {
        return (ret);
    }

    *v = NULL;
    if ((n = strie_search(t, k))) {
        *v = n->v;
        ret = true;
    }

    return (ret);
}

/**
 * Given full command, strip  the user input words, build the args and then 
 * call the registered call back function 
 *
 * @param[in] t Trie root node
 * @param[in] c Command
 *
 * @return \c true if an exact match was found for \c c
 */
bool strie_find_exact (trie *t, char *c)
{
    trie *n = NULL;
    char *k = calloc(1, strlen(c) + 1);
    bool ret = false;
    bool no, help;
    
    if (!k) {
        return (ret);
    }

    if (!strie_mk_key(c, k, &no, &help)) {
        free(k);
        return (ret);
    }

    if (! (n = strie_search(t, k))) {
        help ? cli_lib_help(), ret = true : (ret = false);
    } else {
        if (help) {
            printf("\n\t%s\n", strie_get_node_help(n)); /* automore not req */
        } else {
            pluck_args (t, k); /* build args list */
            n->f ? n->f(no, nargs, args) : 0; /* call the registered 
                                                 handler if any */
        }
        ret = true;
    }
    free(k);

    return (ret);
}

/**
 * Given prefix, display all commands that can complete from there 
 *
 * @param[in] t Trie root node
 * @param[in] p Command prefix
 */
bool strie_what_next (trie *t, char *p)
{
    trie *n = NULL;
    bool no, g, ret = true;
    char *k = calloc(1, strlen(p) + 1);

    if (!k) {
        return (false);
    }

    if (!strie_mk_key(p, k, &no, NULL)) {
        free(k);
        return (false);
    }

    if ((n = strie_find_pfxnod(t, k, &g))) {
        strie_display_possibles(n, no, k);
    } else {
        if (no && !strlen(k)) {
            strie_display_possibles(t, no, k);
        } else  {
            ret = false;
        }
    }
    free(k);

    return (ret);
}

/**
 * Given prefix \c p, get the rest of the word from trie which can complete
 *
 * @param[in] t Trie root node
 * @param[in] p Command prefix
 * @param[out] r  'rest' of the command, update with what is found 
 * @param[out]  read_inp  set to True to tell the main loop to read user input
 *
 * @return  True if we found a completion
 * @warning  this function is too fragile! :( - modify at your own risk! 
 */
bool strie_find_completion (trie *t, char *p, char *r, bool *read_inp)
{
    trie *n = NULL;
    char *k = calloc(1, strlen(p) + 1);
    bool no, traversed = false, inp_gobbled, help;

    if (!k) {
        return (false);
    }

    if (!strie_mk_key(p, k, &no, &help)) {
        free(k);
        return (false);
    }

    *read_inp = false; 
    if ((n = strie_find_pfxnod(t, k, &inp_gobbled))) {
        if (n->sp) {
            *r++ = ' '; 
        }
        if (inp_gobbled) {
            if (n->linkcnt == 1) {
                *r++ = LIDX2CHAR(n->flidx);
                n = n->link[n->flidx];
            }
        }
        while (n->linkcnt == 1 && !n->eow && !n->uinp) {
            if (n->sp) {
                *r++ = ' ';
            }
            *r++ = LIDX2CHAR(n->flidx);
            n = n->link[n->flidx];
            traversed = true; /* traverse as far as possible */
        }
        if (n->uinp ) {
            *r++ = ' ';
            *read_inp = true; /* signal main loop to read input */
            return (true);
        } 
        if (n->sp && traversed) {
            *r++ = ' '; /* add sp aftr full word compl */ 
        }
        if (strlen(p) == 2 && no) {
            *r++ = ' ';
        }
        if (strlen(p) == 4 && help) {
            *r++ = ' ';
        }
    } else {
        if (no && !strlen(k)) {
            strie_display_possibles(t, no, k);
        }
    } 
    free(k);

    return (true);
}

/**
 * @}
 */
