/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "automore.h"
/**
 * @file 
 *
 * Poor man's More handling!
 * with no real tty interaction, just string tokenization
 */

#define REVERSE_VIDEO "[7m"
#define CLEAR         "[0m"

/**
 * @defgroup Terminal_Pager  More handling
 * @{
 */
static int lines_on_term; /* lines printed on terminal */
static bool size_changed;
static bool more_quit;
static bool disabled;
char bigbuf[80*25]; /* TODO can we get something bigger than this ? */

/**
 * The SIGWINCH signal handler
 *
 * We dont want do do an \c ioctl() each time window size changes, 
 * we just set a flag, and when needed we do the \c ioctl()
 * @param[in] s Signal number (unused)
 */
static void winch_hdl (int s) 
{
    /* To avoid doing an ioctl() for each winch, we'll set a flag here
     * and do the ioctl() in get_winsz() if needed */
    size_changed = true;
}

/**
 * Get terminal height and width
 *
 * If window size hasnt changed, we just return the locally stored values
 * If not, we do the \c ioctl() and save the new height and width
 *
 * @param[out] l Length (rows) of the terminal window
 * @param[out] c Columns (width) of the terminal window
 *
 * @return True if we could fetch the window size (we can fail only if
 * \c ioctl() fails)
 */
bool get_winsz (int *l, int *c)
{
    struct winsize ws;
    static int lines, columns; 

    if (size_changed) {
        /* do a ioctl only if we had got a winch (see man tty_ioctl) */
        if (ioctl(STDIN_FILENO, TIOCGWINSZ,&ws)!=0) {
            perror("TIOCGWINSZ");
            return false;
        }
        lines = ws.ws_row;
        columns = ws.ws_col;
    }
    (l) ? (*l = lines - 4) : 0;
    (c) ? (*c = columns) : 0;
    return true; 
}

/**
 * Initialise the \c tty_pager
 *
 * We register for the SIGWINCH signal, force an \c ioctl() the first time
 * This is to be called only once in the start of lib init 
 */
void cli_automore_init ()
{
    /* register a winch handler */
    if (SIG_ERR == signal(SIGWINCH, winch_hdl)) {
        perror("signal"); 
        return;
    } 
    size_changed = true; /* force a ioctl() at start */
    disabled = false;
}

/**
 * In case of input from stdin (not connected to tty), disable
 */
void cli_automore_disable()
{
    disabled = true;
}

/**
 * Begin sending some data to the terminal 
 *
 * This is to be called before each CLI/set of display
 */ 
void cli_automore_begin ()
{
    lines_on_term = 0;
    more_quit = false;
}

/**
 * Display the prompt and wait for user input
 *
 * wait until valid input
 */
static void more_prompt ()
{
    int n, c;

    get_winsz(&n, NULL);
    if (lines_on_term >= n) { 
        printf ("\n" REVERSE_VIDEO MORE_PROMPT CLEAR);
        fflush(stdout);
        c = getch(true);
        while (1) {
            switch(c) {
                case 'q':
                case 'Q':
                    more_quit = true;
                    printf("\r%s\r", MORE_CLEAR);
                    fflush(stdout);
                    return;
                case ' ':
                case '\n':
                    printf("\r%s\r", MORE_CLEAR);
                    fflush(stdout);
                    lines_on_term = 0;
                    break;
                default:
                    printf("\a");
                    c = getch(true);
            }
            if (!lines_on_term) break;
        } /* while (valid user input) */
    } /* if ( we have some lines to display) */
}

/**
 * The print function 
 *
 * Signature same as that of \c printf, does a simple tokenisation 
 * on newlines and tries to fit this to the current terminal size
 *
 * @param[in] fmt Format string 
 * @return  whatever \c vsprintf returns 
 */
int cli_automore_print (const char * fmt, ...)
{
    va_list ap;
    int ret, width; 
    char *p;

    if (more_quit) 
        return 0; /* if user indicated no more output, all further prints
                     disabled until cli_automore_begin() [until next run] */
    if (disabled) {
        va_start(ap, fmt);
        ret =  vprintf(fmt, ap); 
        va_end(ap);
        return ret;
    }
    get_winsz(NULL, &width);
    va_start(ap, fmt);
    ret = vsprintf(bigbuf, fmt, ap); 
    va_end(ap);
    p = strtok(bigbuf, "\n");
    if (p) {
        printf("%s\n", p);
        lines_on_term ++;
        strlen(p) > width ? lines_on_term ++ : 0;
    }
    more_prompt();
    while ((p = strtok(NULL, "\n"))) {
        printf("%s\n", p);
        lines_on_term ++;
        strlen(p) > width ? lines_on_term ++ : 0;
        more_prompt();
    }
    return ret;
}

/**
 * @}
 */
