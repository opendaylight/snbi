/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */



#include <unistd.h>
#include <stdio.h>
#include <termios.h>
#include <stdbool.h>
#ifndef __TERMIO_H
#define __TERMIO_H

#define KEY_ESC        27
#define KEY_LINEKILL   21  /* CTRL + U  */
#define KEY_BS          8  /* Backspace */ 
#define KEY_DEL       127  /* Delete    */
#define KEY_WORDKILL   23  /* CTRL + W  */
#define KEY_CLS        12  /* CTRL + L  */
#define KEY_SPL        22  /* CTRL + V (treat the following character 
                                        literally) */
#define CHR_ENTER     '\n'
#define CHR_TAB       '\t'
#define CHR_SPACE     ' '
#define CHR_COMMENT   '#'

#define CHR_PILCROW   0xB6

#define ASCII_CURSORHOME  "\033[H"
#define ASCII_CLS         "\033[2J"

/**
 * The scancode after ESC has been stripped
 */
#define KEY_UP    0x415B
#define KEY_DOWN  0x425B

int  getch (bool wait);
bool is_ctrl (int c);
bool is_arrow (int* c);

#endif 
