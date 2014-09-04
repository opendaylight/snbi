/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <locale.h>
#include <libgen.h> /* POSIX versions for path tokenisation */
#include <stdlib.h>
#include "libcli.h"
#include "flread.h"
#include "automore.h"

#define LIBCLI_MAJVER   "1"
#define LIBCLI_MINVER   "6"

#define MAXMATCHES 30
#define MAXHIST    10
#define INVALID_CHAR INT_MAX
#define ASCII_MAX    127
#define CLI_ALIAS_PRINT_FMT " %30s | %s"

static bool   g_lib_inited = false;
static trie  *g_rc_t = NULL;       /* trie for rc shortcuts (aliases) */
static trie  *g_var_t = NULL;      /* trie for variables (var => value)*/
static trie  *g_var_rev_t = NULL;  /* trie for variable names itself (var => var) */
static FILE*  g_cmd_log = NULL;    /* file for logging commands executed */
static bool   g_interactive = true;

#define ASSERT_SET_T(_S, ...)  \
    do {                                                                     \
        if(!_S) {                                                            \
            fprintf(stderr, "\nCLI: %s: invalid set `" #_S "'!\n",__func__); \
            return __VA_ARGS__;                                              \
        }                                                                    \
    } while(0)


#define CHECK_DESTROY(_T) \
    do {                                                             \
        if(_T) {                                                     \
            strie_destroy(_T);                                       \
            _T = NULL;                                               \
        }                                                            \
    } while(0)

/**
 * If we have some cleanup activities, do them before exiting
 *
 */
static void cli_cleanup ()
{
    /* open file handles will be closed by the time we reach here */
    CHECK_DESTROY(g_rc_t);
    CHECK_DESTROY(g_var_t);
    CHECK_DESTROY(g_var_rev_t);
}

/**
 * Dump 1 alias (as key, value pair) 
 *
 * @param[in] t      Trie node to print the values from 
 * @param[in] data   Pointer to user data if passed
 */
static void cli_print_an_alias (trie *t, void *data)
{
    cli_automore_print("\n" CLI_ALIAS_PRINT_FMT, strie_get_node_help(t),
                       strie_get_node_val(t));
}

/**
 * Match the regex against the command and help, display if 
 * there is a match
 *
 * @param[in] t      Trie node to print the values from 
 * @param[in] data   Pointer to user data if passed
 */
static void cli_print_matched_cmd (trie *t, void *data)
{
#define MATCH_MAX  2
#define BG_RED     "[41m"
#define FG_RESET   "[0m"
#define LINE_MAX2  (LINE_MAX * 2)
    char *in_pat = (char *)data;
    char  pattern[LINE_MAX] = {0};
    int   status, b, e;
 // int n;
    char  tmpbuf[LINE_MAX2] = {0};
    char  cbuf[LINE_MAX2] = {0};
    regex_t    re;
    regmatch_t matches[MATCH_MAX];

    strcpy(pattern, "(");
    strcat(pattern, in_pat);
    strcat(pattern, ")");
    if (regcomp(&re, pattern, REG_EXTENDED) != 0) {
        fprintf(stderr, "\nCLI: Failed to compile regex!\n");
        return;
    }
    snprintf(tmpbuf, LINE_MAX2, " Cmd: %s\n\tHelp: %s\n", strie_get_node_val(t),
            strie_get_node_help(t));
    status = regexec(&re, tmpbuf, MATCH_MAX, matches, 0);
    if (status == 0) {
  //      n = strlen(tmpbuf);
        b = matches[1].rm_so;
        e = matches[1].rm_eo;
        strncpy(cbuf, tmpbuf, b);
        printf("%s", cbuf); 
        cbuf[0] = 0;
        strncpy(cbuf, tmpbuf + b, e - b);
        cbuf[e - b] = 0;
        printf(BG_RED "%s" FG_RESET, cbuf); 
        cbuf[0] = 0;
        strcpy(cbuf, tmpbuf + e);
        printf("%s", cbuf); 
    }
    regfree(&re);
}

/**
 * Callback for 'alias' command.
 *
 * Display all aliases, and variables if an rc file was read.
 * Walk the global rc trie, and call \c cli_print_an_alias for each
 * node
 *
 * Standard args of command callback (none used)
 * @param[in] no   If this were a 'no' form
 * @param[in] argc Number of arguments for command
 * @param[in] argv The command args
 * @ingroup Customization
 */
static void cli_list_alias (bool no, int argc, char *argv[])
{
    if (!g_rc_t || !g_var_t) {
        return; /* No rc file */
    }
    printf("\n\n" CLI_ALIAS_PRINT_FMT, "Alias", "Expansion");
    printf("\n -------------------------------+"
           "-----------------------------------\n");
    cli_automore_begin();
    strie_walk(g_rc_t, cli_print_an_alias, NULL);
    printf(" -------------------------------+"
           "-----------------------------------");
    printf("\n" CLI_ALIAS_PRINT_FMT, "Variable", "Expansion");
    printf("\n -------------------------------+"
           "-----------------------------------\n");
    strie_walk(g_var_t, cli_print_an_alias, NULL);
}

/**
 * Holder function for the top level trie, which was given to us
 * from \c cli_init
 *
 * @param[in]  t   Trie root node (to set), or NULL (to get)
 * @return saved trie root node
 */
static trie* cli_top_trie (trie *t)
{
    static trie *myt;

    if (t) {
        myt = t;
        return NULL;
    } else  {
        return myt;
    }
}

/**
 * Search all the top level trie command and help strings for the given
 * regex pattern - similar to the apropos(1) command
 *
 * Standard args of command callback 
 * @param[in] no   If this were a 'no' form
 * @param[in] argc Number of arguments for command
 * @param[in] argv The command args
 */
static void cli_search_cmds (bool no, int argc, char *argv[])
{
    trie *t = cli_top_trie(NULL);

    if (!t) {
        return;
    }
    printf("\n\n Matches ...\n");
    if ((argc != 1) || (!argv[0])) {
        fprintf(stderr, "\nCLI: Error: no regex given!\n"); 
        return;
    }
    puts("");
    cli_automore_begin();
    strie_walk(t, cli_print_matched_cmd, argv[0]);
}

/**
 * Clear the current line (fetching width from terminal size)
 */
static void cli_clear_line ()
{
    int term_width, i;

    putchar('\r');
    get_winsz(NULL, &term_width);
    for(i = 0; i < term_width; i++) {
        putchar(' ');
    }
}

/**
 * Print the current prompt (including the submode in parens)
 *
 * @param[in] s         CLI set of the top level mode
 * @param[in] newline   If newline is to be printed, if not, carriage return
 *                      is printed
 */
static void cli_print_prompt (cli_set_t *s, bool newline) 
{
    cli_set_t *p = s;

    while (p->next != NULL) {
        p = p->next;
    }
    putchar(newline ? '\n' : '\r');
    printf("%s", s->prompt);
    if (p && p != s) {
        printf("(%s)", p->prompt);
    }
    printf("> ");
}

/**
 * Get the current prompt len (plus the submode prompts)
 *
 * @param[in] s Cli set of the top mode
 *
 * @return Length of the prompt including submode prompts
 */
static int cli_prompt_len (cli_set_t *s)
{
    cli_set_t *p = s;
    int i;

    while (p->next != NULL) {
        p = p->next;
    }
    i = p ? p->plen : 0;
    return s->plen + i + 4 /* ( ) > SP */;
}

/** 
 * Initialize the CLI library 
 *
 * Sets up the prompt and the Trie root node in the cli_set
 *
 * @param[in]   prompt    The CLI Prompt string
 * @param[in]   exit_cmd  The command to exit the CLI
 * @param[in]   exit_fp   Callback function when \c exit_cmd is entered
 *
 * @return  A pointer to the CLI set to which commands can be inserted
 * with \c cli_insert
 *
 * @note \c exit_cmd is one mandatory command, even if no other commands
 * exist, this must be there. Users can add other commands to exit the
 * CLI (this is where all the cleanup shall happen before exiting)
 */
cli_set_t* cli_init (const char* prompt, const char* exit_cmd, cbk_t exit_fp)
{
    trie *t = strie_newnode ();
    cli_set_t *s = calloc (1, sizeof(cli_set_t));

    if (!t || !s) {
        return NULL;
    }

    if (!setlocale(LC_ALL, "C")) {
        return NULL;
    }

    s->t = t;
    s->prompt = strdup(prompt);
    assert(s->prompt);
    s->plen = strlen(prompt);
    s->periodic = NULL; /* cli_set_periodic to be called to set this */
    /* Initialise terminal pager */
    cli_automore_init();
    cli_automore_begin();

    if (atexit(cli_cleanup) != 0) {
        return (NULL);
    }

    g_lib_inited = true;
    cli_insert(s, exit_cmd, "Exit", exit_fp, false);
    cli_insert_hidden(s, "alias", cli_list_alias, false);
    cli_insert_hidden(s, "apropos <regex>", cli_search_cmds, false);
    cli_top_trie(s->t);
    return (s);
}

/**
 * Check if the CLI library is initialised
 *
 * @param[in] s The CLI set
 * @return true if initialised
 */
static bool cli_lib_initialised (cli_set_t *s)
{
    if (!g_lib_inited) {
        printf("\nCLI Lib not initialised\n");
        return (false);
    }
    return (true);
}

/**
 * Trim the command string
 *
 * The input command in \c c is trimmed, and the word in user input
 * markers between \c < and \c > is skipped, and in its position
 * a single character \c '@' is added - which the Trie understands.
 * (this is just to keep the processing in the Trie simple)
 *
 * @param[in]  c   The command string (multiple spaces will be ignored
 *                 any character not in the input alphabet will
 *                 throw an error message and insertion into the 
 *                 Trie shall fail.
 * @param[in]  n   Length of \c c
 * @param[out] k   The trimmed command string - ready to be inserted to
 *                 the Trie.
 *
 * @return True on trim successful
 *
 * @note  Responsibility of the caller to allocate \c k 
 */
static bool cli_mk_valid_cmd (const char *c, int n, char *k)
{
    int i, j, s;
    int args = 0;

    if (n > MAXLINE) {
        fprintf(stderr, "\nCLI: Error: command exceeds max length!\n"); 
        return (false);
    }
    i = j = 0;
    while (c[i] == ' ') {
        i++; /*  skip leading sp */
    }
    while (c[n - 1] == ' ') {
        n--; /* skip trailing sp */
    }
    for ( ; i < n; i++) {
        if ((c[i] == c[i+1]) && (c[i] == ' ' || c[i] == '\t')) {
            k[j++] = ' ', i++; /* reduce multiple sp/tab to single sp */
        } else if (c[i] == '<') {
            s = i;
            while (c[i] && c[i] != '>') {
                i++;
            }
            if (strncmp(c+s, OPT_MARKER, OPT_MARKER_LEN) == 0) {
                k[j++] = '#';
            } else {
                k[j++] = '@';
            }
            args++;
        } else {
            if (c[i] == '@' || c[i] == '#') {
                fprintf(stderr, "\nCLI: Error: `@' and `#' not allowed in"
                                " commands");
                return (false);
            }
            k[j++] = c[i];
        }
        if (args > MAX_CLI_ARGS) {
            fprintf(stderr, "\nCLI: Error: command can have max %d args!\n", 
                    MAX_CLI_ARGS); 
            return (false);
        }
    }

    return (true);
}

/**
 * Insert a trimmed command string into the Trie
 *
 * @param[in]  s   The CLI set to which this belongs
 * @param[in]  c   The raw command string 
 * @param[in]  h   Command's help string
 * @param[in]  fp  Pointer to the callback function on successful match
 *                 of command \c c
 * @param[in]  no  Whether a 'no' form of this command is needed
 *
 * @return True on successful insertion of the command to Trie
 */
bool cli_insert (cli_set_t *s, const char *c, const char *h,
                 cbk_t fp, bool no)
{
    char *k = NULL;
    int n = strlen(c);

    if (!cli_lib_initialised(s)) {
        return (false);
    }
    k = calloc (1, n + 1);
    if (!k)  {
        return (false);
    }
    if (cli_mk_valid_cmd(c, n, k)) {
        strie_insert(s->t, k, c, h, fp, no);
    }
    free(k);
    s->num_clis ++;
    return (true);
}

/**
 * Insert a hidden command
 *
 * @see \c cli_insert, similar, but no help, hence, command not 
 * displayed on '?'
 *
 * @param[in]  s   The CLI set to which this belongs
 * @param[in]  c   The raw command string 
 * @param[in]  fp  Pointer to the callback function on successful match
 *                 of command \c c
 * @param[in]  no  Whether a 'no' form of this command is needed
 *
 * @return True on successful insertion of the command to Trie
 */
bool cli_insert_hidden (cli_set_t *s, const char *c, 
                        cbk_t fp, bool no)
{
    char *k = NULL;
    int n = strlen(c);

    if (!cli_lib_initialised(s)) {
        return (false);
    }
    k = calloc (1, n + 1);
    if (!k) {
        return (false);
    }
    if (cli_mk_valid_cmd(c, n, k)) {
        strie_insert(s->t, k, NULL, NULL, fp, no);
    }
    free(k);
    s->num_clis ++;
    return (true);
}

/**
 * Insert a command with options (keywords)
 *
 * Each occurence of the sub-string "<OPT>" in the command \c c
 * is replaced with the option, and inserted into the Trie.
 *
 * @param[in]  s     The CLI set to which this belongs
 * @param[in]  c     The raw command string 
 * @param[in]  h     Command's help string
 * @param[in]  fp    Pointer to the callback function on successful match
 *                   of command \c c
 * @param[in]  no    Whether a 'no' form of this command is needed
 * @param[in]  opts  An array of C-strings, NULL terminated
 *
 * @return True on successful insertion of the command to Trie
 *
 * @note   This will insert multiple commands into the Trie
 *         (as many as the number of elements in the \c opts array)
 */
bool cli_insert_opts (cli_set_t *s, const char *c, const char *h,
                      cbk_t fp, bool no, char **opts)
{
    char *k = NULL;
    int n = strlen(c);

    if (!cli_lib_initialised(s)) {
        return (false);
    }

    k = calloc (1, n + 1);
    if (!k)  {
        return (false);
    }
    if (cli_mk_valid_cmd(c, n, k)) {
        strie_insert_opts(s->t, k, c, h, fp, no, opts, NULL, false);
    }
    free(k);
    s->num_clis ++;
    return (true);
}

/**
 * Insert a command with options and values - (key, value) pairs
 * value is an integer which gets converted to a string internally
 *
 * @see cli_insert_opts above - most of the things are similar
 *
 * @param[in]  s     The CLI set to which this belongs
 * @param[in]  c     The raw command string 
 * @param[in]  h     Command's help string
 * @param[in]  fp    Pointer to the callback function on successful match
 *                   of command \c c
 * @param[in]  no    Whether a 'no' form of this command is needed
 * @param[in]  optvals  An array of key,val pairs, NULL terminated
 *
 * @return True on successful insertion of the command to Trie
 */
bool cli_insert_optval (cli_set_t *s, const char *c, const char *h,
                        cbk_t fp, bool no, cli_optval_t *optvals)
{
#define MAXDIGITS   12  /* ~ floor(log10((double)UINT_MAX))+1 */
    char  *k = NULL;
    char **opts = NULL;
    char **valstrs = NULL;
    int    n = strlen(c);
    int    i = 0, nelems = 0;
    char   buf[MAXDIGITS] = {0};
    cli_optval_t *ov = NULL;

    if (!cli_lib_initialised(s)) {
        return (false);
    }

    k = calloc (1, n + 1);
    if (!k)  {
        return (false);
    }
    /* Count the number of elements in the optvals array and split them 
     * into a char arr and an int array
     */
    ov = optvals;
    nelems = 0;
    while (ov && ov->opt) {
        nelems++;
        ov++;
    }
    nelems++; /* for NULL */
    opts = calloc(1, nelems * sizeof(char*));
    valstrs = calloc(1, nelems * sizeof(char*));
    if (!opts || !valstrs)  {
        return (false);
    }
    ov = optvals;
    i = 0;
    while (ov && ov->opt) {
        opts[i] = strdup(ov->opt);
        snprintf(buf, MAXDIGITS, "%d", ov->val);
        valstrs[i] = strdup(buf);
        if (!opts[i] || !valstrs[i])  {
            return (false); /* not enuf!, more l8r*/
        }
        ov++; 
        i++;
    }

    /* Convert the ints to strings - and build a new  array */
    if (cli_mk_valid_cmd(c, n, k)) {
        strie_insert_opts(s->t, k, c, h, fp, no, opts, valstrs, false);
    }
    free(k);
    for (i = 0; i < (nelems - 1); i++) {
        free(opts[i]);
        free(valstrs[i]);
    }
    free(opts);
    free(valstrs);
    s->num_clis ++;
    return (true);
}
/* 
 * Similar to cli_insert_opts, but doesnt consider the command to be
 * complete (helpful while building the command in parts) 
 */
bool cli_insert_opts_noeol (cli_set_t *s, const char *c, const char *h,
                            cbk_t fp, bool no, char **opts)
{
    char *k = NULL;
    int n = strlen(c);

    if (!cli_lib_initialised(s)) {
        return (false);
    }

    k = calloc (1, n + 1);
    if (!k)  {
        return (false);
    }
    if (cli_mk_valid_cmd(c, n, k)) {
        strie_insert_opts(s->t, k, c, h, fp, no, opts, NULL, true);
    }
    free(k);
    s->num_clis ++;
    return (true);
}


/**
 * Deletes a command from the trie
 *
 * This is useful in cases of dynamic addition of commands from other
 * command callbacks, and their removal later on.
 *
 * @param[in]  s  CLI set to delete the command from
 * @param[in]  c  The command to delete
 */
void cli_delete (cli_set_t *s, const char *c)
{
    char *k = NULL;
    int n = 0;

    ASSERT_SET_T(s);
    if(!c) {
        return;
    }
    n = strlen(c);
    k = calloc (1, n + 1);
    if (!k) {
        return;
    }

    if (cli_mk_valid_cmd(c, n, k)) {
        if (!strie_search(s->t, k)) {
            /*
             * Suppress this message for now, because, when a longer 
             * command is deleted, its prefix also goes away, and
             * hence it might not be of concern
             */
            //fprintf(stderr, "\nError: Delete - Unknown Command [%s]\n", k);
            free(k);
            return;
        }
    }
    strie_delete(s->t, k, NULL, 0,0);
    free(k);
}

/**
 * Deletes a command with dynamic options, from the trie
 *
 * This is useful in cases of dynamic addition of commands from other
 * command callbacks, and their removal later on.
 *
 * @param[in]  s    CLI set to delete the command from
 * @param[in]  c    The command to delete
 * @param[in]  opts The options array (\c NULL terminated array of C-strings)
 */
void cli_delete_opts (cli_set_t *s, const char *c, char **opts)
{
    char tmp[MAXLINE] = {0};
    char *p = strstr(c, OPT_MARKER);

    if (!p) {
        fprintf(stderr, "\nCLI: Invalid options command, can't remove"
                        " [%s]\n", c);
        return;
    }

    while (*opts) {
        tmp[0] = '\0';
        strncpy(tmp, c, p - c);
        tmp[p - c] = '\0';
        strcat(tmp, *opts);
        strcat(tmp, p + OPT_MARKER_LEN);
        cli_delete(s, tmp); 
        opts++;
    }
}

/**
 * Show options for the input prefix on '?'
 *
 * @param[in] s   Cli set of the top mode
 * @param[in] pfx Prefix string on the command line
 */
void cli_do_help (cli_set_t *s, char *pfx) 
{
    cli_set_t *p = s;
    trie *t = NULL;

    ASSERT_SET_T(s);
    t = s->t;
    while (p->next != NULL) {
        p = p->next;
    }
    t = p->t; /* Pick the last pushed mode Trie */
    putchar('\n');
    if (!strie_what_next(t, pfx)) {
        printf("\nNo commands with this prefix\n");
    }
}

/**
 * Execute the command by calling the callback function
 * this is called when ENTER key is pressed
 * 
 * At this point, we assume the command is complete, i.e,
 * it is either a full command as inserted by \c cli_insert
 * or a shortcut from the rc file, in which case, we expand it
 * and retry execution.
 *
 * @param[in] s         CLI set to operate on
 * @param[in] c         The command 
 * @param[in] flags     Control some aspects of execution - like if logging 
 *                      needs to be enabled/command has to echoed
 *
 * @return true if a exact match found 
 */
bool cli_do_cmd_general (cli_set_t *s, char *c, unsigned short flags)
{
    char *rcval = NULL;
    bool retval = false, ignore;
    trie *t = s->t;
    cli_set_t *p = NULL;
    char *cp = c;

    if (cp && (cp[0] == CHR_COMMENT)){
        return true;
    }

    ASSERT_SET_T(s, false);
    p = s;
    while (p->next != NULL) {
        p = p->next;
    }
    t = p->t; /* Pick the last pushed mode Trie */

    while (*cp) {
        if (!(isprint(*cp) || (*cp == (char)CHR_PILCROW))) {
            printf("\n%*c^", (int)((cp - c + 1) + strlen(s->prompt) + 1), ' ');
            printf("\nInvalid Character!\n");
            return false;
        }
        cp++;
    }

    /* Check first in rc trie; (first try expanding as alias) */
    if (strie_get_val(g_rc_t, c, &rcval)) {
        /* show whats expanded ? */
        if (flags & CLI_CMD_ECHO_EXPANDED) {
            cli_print_prompt(s, true);  
            printf("%s", rcval);
        }
        retval = strie_find_exact(t, rcval);
    }
    /* If that fails, try normal command match */
    if (!retval) {
        retval = strie_find_exact(t, c);
    } else {
        c = rcval; /* write expanded cmd to file*/
    }

    if (!retval) {
        printf("\n%s Command\n", 
                strie_find_pfxnod(t, c, &ignore) ? "Incomplete" : "Unknown");
    }
    if (retval && g_cmd_log && (flags & CLI_CMD_LOG)) {
        fprintf(g_cmd_log, "%s\n", c);
        fflush(g_cmd_log);
    }
    return retval;
}

/**
 * Execute the command by calling the callback function
 * this is called when ENTER key is pressed
 * 
 * At this point, we assume the command is complete, i.e,
 * it is either a full command as inserted by \c cli_insert
 * or a shortcut from the rc file, in which case, we expand it
 * and retry execution.
 *
 * @param[in] s CLI set to operate on
 * @param[in] c The command 
 *
 * @return true if a exact match found 
 * @see cli_do_cmd_general
 */
bool cli_do_cmd (cli_set_t *s, char *c)
{
    return cli_do_cmd_general(s, c, CLI_CMD_LOG | CLI_CMD_ECHO_EXPANDED);
}

/**
 * Autocomplete on SPACE or TAB key. 
 *
 * If a possible completion is found, then the cli and its length are 
 * updated, if not, search in the rc trie assuming prefix is a shortcut
 * @note the prefix is overwritten when it is found in the rc trie
 *
 * @param[in]      s     CLI set to operate on
 * @param[in,out]  pfx   The command prefix (that is on the command line)
 * @param[out]     len   The length of the command line
 * @param[out]     read  If true - the main input loop must change to 
 *                       user input mode to read a word
 *
 * @return True if we found a completion
 */
static bool cli_do_space (cli_set_t *s, char *pfx, int *len, bool *read)
{
    char   rest[MAXLINE] = {0};
    char  *rcval = NULL;
    int    n = 0;
    cli_set_t *p = s;
    trie      *t = s->t;

    while (p->next != NULL) {
        p = p->next;
    }
    t = p->t; /* Pick the last pushed mode Trie */

    /* Search the rc trie for this prefix first (i.e, try alias expansion) */
    if (strie_get_val(g_rc_t, pfx, &rcval)) {
        cli_print_prompt(s, true); /* show whats expanded */
        printf("%s", rcval);
        strcpy(pfx, rcval);        /* Overwrite prefix; assume prefix is 
                                      at beginning of command */
        *len = strlen(rcval);
        /* run the expanded command through the cli_loop */
    } 

    /* 'read' decides whether to next read user input */
    strie_find_completion(t, pfx, rest, read);
    n = strlen(rest);
    if (n) {
        strcat(pfx, rest);
        *len += n;
    }

    return n;
}

/**
 * @defgroup FileCompletion   File completion functions
 */

/**
 * Find the longest matching prefix for the current user input
 * The prefix may/may not be a full file name
 *
 * @param[in,out]  name_found The current longest prefix 
 * @param[in]      name_len   Length of \c name_found 
 * @param[in]      cur_file   A file name from the same directory to compare
 *                            with \c name_found
 * @param[in]      cur_flen   Length of \c cur_file  
 * @return \c name_found will contain the longest prefix of
 *              (\c name_found, \c cur_file)
 * @ingroup  FileCompletion
 */
static void cli_flcomp_longest_prefix (char *name_found, int name_len, 
                                       char *cur_file, int cur_flen)
{
    int i, minlen;

    if (!name_len) {
        strcpy(name_found, cur_file);
        return;
    }
    minlen = (name_len < cur_flen) ? name_len : cur_flen;
    for (i = 0; i < minlen; i++) {
        if (name_found[i] != cur_file[i]) {
            break;
        }
    }
    strncpy(name_found, cur_file, i); /* cp longest prefix matched so far */
    name_found[i] = '\0';
}

/**
 * Get a file name matching the prefix entered
 *
 * @param[in]      d     The directory point to read file names from
 * @param[in]      dp    The directory name (from \c dirname() )
 * @param[in]      wp    The user entered word prefix (from \c basename() )
 * @param[in,out]  name_found The current longest prefix 
 * @param[out]     max_flen   Maximum length of filename in the directory \c d
 *                            We will use this as a width specifier when 
 *                            listing all the possible completions
 * @param[out]    full_name_compl  What we have in \c name_found is a full 
 *                                 file name or just a prefix
 * @return The number of matches for prefix \c wp or all the files if
 *         \c wp were empty
 *
 * @ingroup FileCompletion
 */
static int cli_flcomp_get_match (DIR *d, char *dp, char *wp, 
                                 char *name_found, int *max_flen,
                                 bool *full_name_compl) 
{
    struct dirent *dirp;
    int wplen = 0;
    char buf[PATH_MAX] = {0};
    struct stat st;
    int matches = 0, flen, maxw = 0;

    *full_name_compl = false;
    if (wp) wplen = strlen(wp);
    rewinddir(d);
    while ((dirp = readdir(d))) {
        if ((0 == strcmp(dirp->d_name, ".")) || 
                (0 == strcmp(dirp->d_name, "..")) ) {
            continue;
        }
        if (!wp) {
            matches ++;
            flen = strlen(dirp->d_name);
            if (flen > maxw) {
                maxw = flen;
            }
        } else if (strncmp(dirp->d_name, wp, wplen) == 0) {
            matches ++;
            flen = strlen(dirp->d_name);
            if (flen > maxw) {
                maxw = flen;
            }
            cli_flcomp_longest_prefix(name_found, strlen(name_found),
                                      dirp->d_name, flen);
        }
    }
    *max_flen = maxw;
    snprintf(buf, PATH_MAX, "%s/%s", dp, name_found); 
    /* 
     * If a word-prefix was given and stat suceeds, 
     * what we completed is the full filename 
     */
    if (wp && stat(buf, &st) != -1) {
        *full_name_compl = true;
        if (S_ISDIR(st.st_mode) && wp && matches) 
            strcat(name_found, "/"); /* if dir were empty, dont bother 
                                        to add a '/' */
        /* 
         * Avoid adding trailing sp - even if we found a complete file name
         * it can be a prefix of some other file name 
         * TODO: should we check this cond for dirs as well - i.e, if we have 
         * a dir name which is a prefix of another ... ?
         */
    }

    return (matches);
}

/**
 * Display all matches for the user given prefix from the current directory
 *
 * @param[in]   d       The directory point to read file names from
 * @param[in]   wp      The user entered word prefix (from \c basename() )
 * @param[in]   matches Number of matches found for prefix \c wp
 * @param[in]   maxw    Max width - the length of the longes file name 
 *                      in directory \c d (used for formatting display)
 * @ingroup FileCompletion
 */
static void cli_flcomp_disp_all_match (DIR *d, char *wp, int matches, int maxw)
{
    int yn;
    int addnl = maxw;
    int wplen = 0, term_width;
    struct dirent *dirp;

    get_winsz(NULL, &term_width);
    if (wp) {
        wplen = strlen(wp);
    }
    if (matches > MAXMATCHES) {
        printf("\nDisplay all %d possibilities? (y or n)", matches);
        fflush(stdout);
        yn = getch(true);
        if (yn != 'y' && yn != 'Y') {
            return;
        }
    }
    rewinddir(d);
    putchar('\n');
    while ((dirp = readdir(d))) {
        if (0 == strcmp(dirp->d_name, ".") || 
                0 == strcmp(dirp->d_name, "..")) {
            continue;
        }
        if (!wp || strncmp(dirp->d_name, wp, wplen)== 0) {
            printf("%-*s ", maxw, dirp->d_name);
            addnl += (maxw + 1); /* 1 for sp above */
            if ((addnl + maxw + 1) > term_width) {
                putchar('\n');
                addnl = 0;
            }
        }
    }
    fflush(stdout);
}

/**
 * Expand the variable and interpolate in the command string
 *
 * Limitation - currenly we can only interpolate 1 var at a time (on TAB) 
 *
 * @param[in,out]   var  Pointer to the command line, pointing at $ sign
 * @param[out]      l    Length of the command line
 */
static void cli_interpolate_var (int *l, char *var)
{
    char *p = (var + 1), *dollar = var, *val = NULL;
    char v[MAXLINE] = {0}, rest[MAXLINE] = {0};
    int  varlen = 0, n;
    bool read;

    while (p && isalnum(*p)) { /* assume var name as alphanumeric */
        p++;
    }
    varlen = (p - var - 1); 
    if (!varlen) {
        /* TAB immediately after $ sign without any names */
        printf("\n\n");
        strie_what_next(g_var_rev_t, ""); /* Display known variables*/
        return;
    }
    strcpy(rest, p);
    strncpy(v, var + 1, varlen);
    if (strie_get_val(g_var_t, v, &val)) {
        /* value found, interpolate and update the length */
        *dollar = '\0';
        strcat(var, val); 
        *l += (strlen(val) - varlen - 1);
        strcat(var, rest); /* Len of this already considered in the caller */
    } else {
        /* 
         * No value found, but this could be a partial var name 
         * try expanding the var name itself using the key=>key trie 
         * (which maps var name to name itself)
         */
        rest[0] = '\0';
        strie_find_completion(g_var_rev_t, dollar + 1, rest, &read);
        n = strlen(rest);
        if (n) {
            strcat(var, rest); 
            *l += n;
        }
    }
}

/** 
 * Try to complete the user input as a file/path
 * This is invoked on TAB
 *
 * @param[in,out]  c  The current command line
 * @param[out]     l  Length of command line (\c c )
 *
 * @return True if completion happened
 *
 * @ingroup FileCompletion
 */
bool cli_do_file_compl (char *c, int *l)
{
    DIR *d;
    char name_found[PATH_MAX] = {0};
    char word1[PATH_MAX] = {0}, word2[PATH_MAX] = {0};
    char *dp, *wp, *t, *p = NULL;
    bool noword = false, full_name_comp;
    int  matches = 0, maxw = 0,  wplen, n;
    bool ret = false;

    /* 
     * From end of command, traverse backward till a SPACE is found,
     * and copy the last word 
     * this must work because we can never read user input or do 
     * a file completion as the first word 
     */
    t = c + strlen(c);  
    while (*t != ' ') {
        t--; 
    }
    t++;

    if ((p = strchr(t, '$'))) {
        cli_interpolate_var(l, p); /* Try to expand variables */
        ret = true;
    }
    strcpy (word1, t);
    strcpy (word2, t);
    /* 
     * if last char were a '/', add a dummy char so that (dir|base)name
     * calls work as usual 
     */
    if (word1[strlen(word1)-1] == '/') {
        strcat(word1, "X");
        strcat(word2, "X");
        noword = true;
    }
    wp = basename(word1); 
    dp = dirname (word2); /* If empty, dp will automatically be '.' */
    wplen = strlen(wp);
    if (noword)  { 
        wp = NULL;
        wplen = 0;
    }
    if (!(d = opendir(dp))) {
        putchar('\a');
        return (false);
    }
    /* 
     * Try to see if we get some matches, if yes, copy
     * the first match to `name_found', also keep track of the max file name
     * length in the dir 
     */
    matches = cli_flcomp_get_match(d, dp, wp, name_found, &maxw, 
                                   &full_name_comp); 
    /* 
     * This following is basically to just display all names 
     * (if no prefix given)  or, all names that match the given prefix 
     */
    if (!full_name_comp) {
        cli_flcomp_disp_all_match(d, wp, matches, maxw);
    }
    n = strlen(name_found);
    if (n && n > wplen) {
        strcat(c, name_found + wplen); /* add remaining */
        *l += n - wplen;
        ret = true;
    }
    if (matches > 1) {
        ret = true;
    }
    closedir(d);

    return (ret);
}

/**
 * @defgroup NonInteractiveCmd Non Interactive execution functions
 */

/**
 * For each line we obtained from the file/stdin, interpret it as a 
 * full command and execute
 *
 * @param[in] line  Line read from the file
 * @param[in] data  Opaque data passed from the file reader
 *
 * @ingroup NonInteractiveCmd
 */
static void cli_run_from_file (char *line,  void *data)
{
    cli_print_prompt(data, true);
    printf("%s", line);
    cli_do_cmd(data, line);
}

/**
 * Read lines from file (given on the command line) and 
 * interpret them as complete command and run 
 *
 * @param[in]   s         The CLI command set
 * @param[in]   filename  Passed from the command line (for \c -f )
 *
 * @ingroup NonInteractiveCmd
 */
void cli_cmd_file (cli_set_t *s, char *filename) 
{
    if (!cli_lib_initialised(s)) {
        return;
    }
    g_interactive = false;
    if (!flread(filename, cli_run_from_file, s)) {
        fprintf(stderr, "\nCLI: Failed to open command file `%s`\n", filename);
    }
    putchar('\n');
}

/**
 * Read lines from stdin 
 * interpret them as complete commands and run 
 *
 * @param[in]   s   The CLI command set
 *
 * @ingroup NonInteractiveCmd
 */
void cli_cmd_stdin (cli_set_t *s)
{
    if (!cli_lib_initialised(s)) {
        return;
    }
    g_interactive = false;
    stdin_read(cli_run_from_file, s);
}

/**
 * @defgroup Customization Customization/command aliases
 */

/** 
 * Store the rc shortcuts (aliases) in a global trie  
 * 
 * We can only have 1 set of aliases for the whole lib 
 *
 * @param[in]  cmd    Alias name
 * @param[in]  value  Expansion for the alias
 *
 * @ingroup Customization
 */
static void cli_insert_alias (char *cmd, char *value) 
{
    char k[MAXLINE] = {0}, v[MAXLINE] = {0};
    char *rcval = NULL;

    if (!g_rc_t) {
        g_rc_t = strie_newnode();
    }
    if (!cmd || !value) {
        return;
    }
    if (cli_mk_valid_cmd(cmd, strlen(cmd), k) && 
            cli_mk_valid_cmd(value, strlen(value), v)) { /* just a trim */
        /*
         * If the value being inserted were already in the rc trie,
         * this shortcut (command) will just be another alias for the same
         * So, find the value of original command and insert for this key
         * too (this allows an alias to be aliased ;-) )
         */
        if (strie_find_exact(g_rc_t, v) && 
                strie_get_val(g_rc_t, v, &rcval)) {
            strcpy(v, rcval);
        }   
        strie_insert(g_rc_t, k, v, k, NULL, false); /* help = key */
    }
}

/** 
 * Store the rc variables in a global trie  
 * 
 * We can only have 1 set of variables for the whole lib 
 *
 * @param[in]  var    Variable name
 * @param[in]  value  Variable value 
 *
 * @ingroup Customization
 */
static void cli_insert_var (char *var, char *value) 
{
    char k[MAXLINE] = {0}, v[MAXLINE] = {0};

    if (!g_var_t) {
        g_var_t = strie_newnode();
        g_var_rev_t = strie_newnode();
    }
    if (!var || !value) {
        return;
    }
    if (cli_mk_valid_cmd(var, strlen(var), k) && 
            cli_mk_valid_cmd(value, strlen(value), v)) { /* just a trim */
        strie_insert(g_var_t, k, v, k, NULL, false); /* help = key */
        strie_insert(g_var_rev_t, k, k, k, NULL, false); /* val = key */
    }
}

/**
 * Parse a line from rc file
 *
 * Try tokenizing a line on '=', or ':=', 
 * in case of '=' treat it as an alias and save it into the global rc trie
 * in case of ':=' treat it as an var and save it into the global var trie
 * Comment lines (beginning with '#') are ignored
 *
 * @param[in] line Line from the rc file
 * @param[in] data Not used 
 *
 * @ingroup Customization
 */
static void cli_rc_cmd (char *line, void *data)
{
    char *cmd = line, *value = NULL;

    while (*line == ' ' || *line == '\t') {
        line++;
    }
    if (*line == '#')  {
        return; /* Ignore comments*/
    }
    value = strstr(line, ":=");
    if (value) {
        *value = '\0';
        value += 2;
        cli_insert_var(cmd, value);
    } else {
        value = strstr(line, "=");
        if (!value) return;
        *value = '\0';
        value += 1;
        cli_insert_alias(cmd, value);
    }
}

/**
 * Read in a rc file
 *
 * use \c filename if given, if not, use \c ~/.clirc from the users home dir
 *
 * @param[in] filename Optional rc filename
 *
 * @ingroup Customization
 */
void cli_read_rc (char *filename)
{
    char def_rc[PATH_MAX] = {0};
    char *home = NULL;

    if (!filename) {
        if (!(home = getenv("HOME"))) {
            fprintf(stderr, "\nCLI: Failed to get users home directory\n");
            return;
        }
        strcpy(def_rc, home);
        strcat(def_rc, "/");
        strcat(def_rc, CLI_RC_DEFAULT);
    }
    flread(filename ? filename: def_rc, cli_rc_cmd, NULL); 
}

/**
 * Log the successfully run commands to a file
 *
 * use \c filename if given, if not, use \c ./clicmds.log
 *
 * @param[in] filename Optional log filename
 *
 * @note This funcitons has to be called after arg parsing, i.e,
 *       Either aftet the call to \c cli_handle_args, or if arg
 *       parsing is handled by the application - call this only 
 *       when we know we will be in interactive mode.  
 *
 * @ingroup Customization
 */
void cli_log_cmds (char *filename)
{
    char *file = filename ? filename : CLI_CMD_LOG_FILE;

    if (!g_interactive) {
        g_cmd_log = NULL;
        return;
    }
    g_cmd_log = fopen(file, "w+");
    if (!g_cmd_log) {
        fprintf(stderr, "\nCLI: Error: Failed to open file `%s'\n", file);
    }
}

/**
 * @defgroup SubMode Sub mode functions
 */

/**
 * Add a submode to the main cli set
 *
 * @param[in] parent Cli set parent
 * @param[in] child  Cli set child, added under the parent
 *
 * @ingroup SubMode
 */
void cli_push_mode (cli_set_t *parent, cli_set_t *child)
{
    cli_set_t *p = parent;

    ASSERT_SET_T(parent);
    ASSERT_SET_T(child);
    while (p->next != NULL) {
        p = p->next;
    }
    p->next = child;
}

/**
 * Destroy everything associated with the set
 *
 * @param[in] s Cli set
 *
 * @ingroup SubMode
 */
void cli_destroy_set (cli_set_t *s)
{
    ASSERT_SET_T(s);
    strie_destroy(s->t);
    free(s->prompt);
    free(s);
}

/**
 * Set the periodic function pointer in cli_set to pfp
 * This function will be called every 0.1 second, if there
 * are no keystrokes/no commands input to cli.
 *
 * @param[in] s    CLI set
 * @param[in] pfp  Periodic function pointer 
 */
void cli_set_periodic (cli_set_t *s, periodic_cbk_t pfp)
{
    ASSERT_SET_T(s);
    if (!s->periodic) {
        s->periodic = pfp;
    } else {
        fprintf(stderr, "\nCLI: Error: Periodic function already"
                        " registered!\n");    
    } 
}

/**
 * To be called on exiting from a submode
 * Pop (and free) the last pushed mode on \c parent
 *
 * @param[in] parent Parent Cli set
 *
 * @ingroup SubMode
 */
void cli_pop_mode (cli_set_t *parent)
{
    cli_set_t *t, *p;

    ASSERT_SET_T(parent);
    t = p = parent;
    while (p->next != NULL) {
        t = p;
        p = p->next;
    }

    cli_destroy_set(p);
    t->next = NULL;
}

/**
 * Wrapper on \c getch() to get the next character to be processed
 *
 * sometimes, if multiple characters are copy/pasted
 * on the console, \c getch() can read upto \c sizeof(int) bytes, and if we 
 * try to interpret it as a single char, we fail. 
 * Instead, we save such multi char input in a local buffer and when called
 * from the main loop, first try to get from the local buffer, if its empty
 * then do a \c getch()
 *
 * @return character to be processed 
 */
static int cli_get_inp ()
{
    int c = 0;
    static char buf[sizeof(int)] = {0};
    static int saved = 0;
    bool inp_read = false;

    if (!saved) {
        /* Try to read only if dont have anything in local buffer */
        c = getch(false);
        if (is_ctrl(c) && !is_arrow(&c)) {
            return (INVALID_CHAR); /* ignore anything other than UP and 
                                      DOWN arrow keys */
        }
        if (c == KEY_UP || c == KEY_DOWN) {
            return (c);
        }
        inp_read = true;
    } 
    if (inp_read && (c > ASCII_MAX)) {
        /* If input can be split and used from buf - do so */
        memcpy(buf, &c, sizeof(int));
        saved = sizeof(int);
    }
    if (saved) {
        c = buf[sizeof(int) - saved]; /* again, endianness dep! */
        saved--;
    } 

    return (c);
}

/**
 * The main command input/execute loop
 *
 * Handles normal input (command mode), user input, does completion
 * using the Trie, stores history ...
 *
 * @param[in] s CLI command set
 */
void cli_loop (cli_set_t *s)
{
    int c, pc = 0;
    int blen = 0;
    char clibuf[MAXLINE] = {0};
    char cli_history[MAXHIST][MAXLINE] = {{0}} ;
    int ncmd = 0, x, histpos = 0;
    int i, l;
    bool read = false, user_inp_mode = false, treat_literal = false;
    bool comment = false;

    ASSERT_SET_T(s);
    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, "\nCLI: For non-interactive mode, use option "
                        "-f <file>\n");
        return;
    }
    if (!cli_lib_initialised(s)) {
        return;
    }

    cli_print_prompt(s, true);
    fflush(stdout);

    while (1) {
        if ((c = cli_get_inp()) == INVALID_CHAR) {
            continue;
        }
        if (!c) {
            if (s->periodic) {
                s->periodic();
            }
            continue;
        }

        switch (c) {

            case CHR_COMMENT:
                 if (comment) {
                     goto store_chr; 
                 }
                if (!blen) {
                    comment = true;
                    goto store_chr; 
                } 
                break;

            case KEY_SPL:
                 treat_literal = true;
                 break;

            case '?': 
                 if (comment) {
                     goto store_chr; 
                 }
                 if (treat_literal) {
                     goto store_chr; /* Yea, yea, I know `goto' is bad*/
                 }
                 cli_do_help(s, clibuf); 
                 cli_print_prompt(s, true);
                 printf("%s", clibuf);
                break;

            case KEY_CLS:
                printf(ASCII_CLS);
                printf(ASCII_CURSORHOME);
                cli_print_prompt(s, false);
                printf("%s", clibuf);
                break;

            case KEY_UP:
                x = (histpos - 1);
                /* cp and display */
                if (x >= 0 && strlen(cli_history[x])) {
                    strcpy(clibuf, cli_history[x]);
                    cli_clear_line();
                    cli_print_prompt(s, false);
                    printf("%s", clibuf);
                    blen = strlen(cli_history[x]);
                    histpos --;
                    fflush(stdout);
                    user_inp_mode = read = false;
                }
                histpos %= MAXHIST;
                break;

            case KEY_DOWN:
                x = (histpos + 1) % MAXHIST;
                /* cp and display */
                if (strlen(cli_history[x])) {
                    strcpy(clibuf, cli_history[x]);
                    cli_clear_line();
                    cli_print_prompt(s, false);
                    printf("%s", clibuf);
                    blen = strlen(cli_history[x]);
                    histpos ++;
                    fflush(stdout);
                    user_inp_mode = read = false;
                } 
                histpos %= MAXHIST;
                break;

            case CHR_ENTER:
                if (blen) {
                    clibuf[blen] = '\0';
                    if(!cli_do_cmd(s, clibuf)) {
                        cli_print_prompt(s, true);
                        fflush(stdout);
                    }
                    /* on just enter */
                    ncmd %= MAXHIST;
                    strcpy(cli_history[ncmd], clibuf);
                    ncmd++;
                    histpos = ncmd;
                    memset(clibuf,0,MAXLINE);
                    blen = 0;
                } 
                cli_print_prompt(s, true);
                fflush(stdout);
                user_inp_mode = read = comment = false;
                break;

            case CHR_TAB:
                c = CHR_SPACE;
                if (comment) {
                    goto store_chr; 
                }
                if (user_inp_mode) {
                    if (cli_do_file_compl(clibuf, &blen)) {
                        cli_print_prompt(s, true);
                        printf("%s", clibuf);
                        break;
                    }
                }
                /* FALL THRU */

            case CHR_SPACE:
                if (comment) {
                    goto store_chr; 
                }
                if (user_inp_mode) {
                    if (pc == c) { 
                        cli_do_help(s, clibuf);
                        cli_print_prompt(s, true);
                        printf("%s", clibuf);
                        break;
                    }
                    if (treat_literal) {
                        c = CHR_PILCROW;
                        goto store_chr; 
                    }
                    /* 
                     * If we got a sp in user_inp_mode, clear flags 
                     * and do completion 
                     */
                    user_inp_mode = false;
                    read = false;
                }
                if (!user_inp_mode) {
                    /* 
                     * All the ?/sp/tab completion has to happen in the 
                     * command mode only 
                     */
                    if (!cli_do_space(s, clibuf, &blen, &read)) {
                        cli_do_help(s, clibuf); /* if no full compl, do '?' */
                    }
                    cli_print_prompt(s, true);
                    printf("%s", clibuf);
                    if (read) {
                        user_inp_mode = true;
                    }
                } 
                break;

            case KEY_BS:
            case KEY_DEL: /* BS may send DEL */
                /* Clear line */
                l = cli_prompt_len(s) + blen;
                putchar('\r');
                for(i = 0; i < l; i++) {
                    putchar(' ');
                }
                /* Remove last char */
                blen--;
                clibuf[blen] = '\0';
                cli_print_prompt(s, false);
                printf("%s", clibuf);
                break;

            case KEY_LINEKILL: /* CTRL + u */
                memset(clibuf,0,MAXLINE);
                blen = 0;
                cli_print_prompt(s, true);
                fflush(stdout);
                user_inp_mode = read = comment = false;
                break;

            case KEY_WORDKILL: /* CTRL + w */
                while (clibuf[blen] != ' ' && blen) {
                    blen--;
                }
                clibuf[blen] = '\0';
                /* 
                 * Lets print the modified command on the next line
                 * instead of cleaning up the current line to print 
                 */
                cli_print_prompt(s, true);
                printf("%s", clibuf);
                fflush(stdout);
                user_inp_mode = read = false;
                break;

store_chr:
            default:
                /* No support for cli editing for now */
                if (!c) break; /* as get_inp can read nul bytes */
                printf("%c",c);
                clibuf[blen++] = c;
                clibuf[blen] = '\0';
                treat_literal = false;
                break;
        }
        fflush(stdout);
        pc = c;
    }
}

/**
 * Get LibCLi version string in  @verbatim <major>.<minor> @endverbatim format
 */
const char* cli_get_version ()
{
    return (LIBCLI_MAJVER "." LIBCLI_MINVER);
}

/**
 * Help in interactive mode
 *
 * Paginated using automore
 */
void cli_lib_help() 
{
    cli_automore_begin();
    cli_automore_print( 
        "\n     \n  \n"  /* automore quirk */
        "\n\tType TAB or SPACE for command completion"
        "\n\t ?          Displays available completions"
        "\n\t <words>    Indicates user input (completion/help disabled"
        "\n\t            until SPACE)"
        "\n\t help       Followed by command displays command specific help."
        "\n\t            Without any argument, displays this menu."
        "\n\t            (completion will not occur for 'help' and 'no')"
        "\n\t alias      Displays all the aliases configured in the rc file."
        "\n\t CTRL+U     Kills the current command line"
        "\n\t CTRL+W     Kills the previous word"
        "\n\t CTRL+L     Clear screen and home the cursor"
        "\n\t CTRL+V     Treat the following character [SPACE/?] literally"
        "\n\t BACKSPACE  Erases previous character"
        "\n\t More       When display is about to exceed screen length"
        "\n\t            --More-- prompt is displayed, where 'q' can be hit"
        "\n\t            to quit; SPACE or RETURN shall display another page"
        "\n"
       );
}
