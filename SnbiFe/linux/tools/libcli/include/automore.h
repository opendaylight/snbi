/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AUTOMORE_H_
#define __AUTOMORE_H_
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include "termio.h" /* automore needs getch from termio */

#ifdef EXTENDED_MORE_PROMPT
#  define MORE_PROMPT  "--More--[Press space to continue, 'q' to quit.]"
#  define MORE_CLEAR   "                                               "
#else
#  define MORE_PROMPT  "--More--"
#  define MORE_CLEAR   "        "
#endif 

int  cli_automore_print(const char *fmt,...);
void cli_automore_begin();
void cli_automore_init();
bool get_winsz(int *lines, int *columns);
void cli_automore_disable();

#endif 
