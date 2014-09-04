/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __FLREAD_H_
#define __FLREAD_H_ 

typedef void (*flread_cbk) (char *line, void *opaque);
int flread(char *fname, flread_cbk hdlr, void *opq);
int stdin_read (flread_cbk hdlr, void *opq);

#endif 
