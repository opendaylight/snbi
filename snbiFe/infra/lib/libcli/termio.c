/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */







#include "termio.h"

/**
 * @file
 *
 * POSIX term handling
 * 
 * @defgroup Tty_services Terminal interaction
 *
 * @{
 *
 */

/**
 * The raw non echoing character read
 *
 * @param[in] wait  whether to wait for a character or not
 *
 * if \c wait is false, in effect, we are doing a \c O_NONBLOCK \c read
 */
int getch (bool wait) 
{
    int buf = 0;
    struct termios old = {0}; /* see 'man 3 termios' */

    if (tcgetattr(0, &old) < 0) {
        perror("tcsetattr()");
    }
    old.c_iflag |= ISTRIP;
    old.c_lflag &= ~ICANON;
    old.c_lflag &= ~ECHO;

    if (wait) {
        old.c_cc[VMIN] = 1; /* wait for at least 1 char in buffer */
        old.c_cc[VTIME] = 0; /* wait indefinitely */
    } else {
        old.c_cc[VMIN] = 0;
        old.c_cc[VTIME] = 1; /* return if no chars in buf, in 0.1 sec */
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &old) < 0) {
        perror("tcsetattr ICANON");
    }
    /* 
     * Using read() instead of getchar() has pros and cons
     * pros - can read control characters also
     * cons - in case of a copy-paste of multiple characters by user,
     * we have to keep a local buffer of 4 chars and exhaust that, then
     * call this function - getch() again
     */
    if (read(STDIN_FILENO, &buf, sizeof (int)) < 0) {
        perror ("read()");
    }
    old.c_lflag |= ICANON;
    old.c_lflag |= ECHO;
    if (tcsetattr(STDIN_FILENO, TCSADRAIN, &old) < 0) {
        perror ("tcsetattr ~ICANON");
    }
    return (buf);
}

typedef union ctrl_ {
    unsigned int a;
    char i[sizeof(int)];
} ctrl_t;

/**
 * Using the ANSI Escape sequence, the control characters like Arrow
 * keys will translate to the sequence
 * ESC [ CHAR  (i.e, for e,g ESC[A is UPARROW; ESC[B is DOWNARROW
 *                try running `cat'and hit a key, escape is displayed as ^[)
 *      dec    hex      
 * ESC = 27    1B 
 * [   = 91    5B
 *
 * @param[in] c  The character read in raw mode 
 */
inline bool is_ctrl (int c)
{
    ctrl_t u;
    
    u.a = 0;
    u.a = c; /* need an endianness hack here! */
    if (u.i[0] == KEY_ESC) {
        return (true);
    }
    return (false);
}

/** 
 * Is this character an UP/DOWN arrow key?
 *
 * If this is indeed an arrow key, remove the lower byte
 * (which is the escape key)
 *
 * @param[in,out] c  The character read in raw mode 
 * @return True if \c c is UP/DOWN arrow
 */
inline bool is_arrow (int* c)
{
    ctrl_t u;
    unsigned int ui = *c;

    u.a = 0;
    u.a = *c; /* need an endianness hack here!*/
    if (u.i[0] == KEY_ESC) {
        ui >>= 8;   /* refer 'man ascii' */
        *c = ui;
        if (ui == KEY_UP || ui == KEY_DOWN) {
            return (true);
        }
    }
    return (false);
}


/**
 * @}
 */
