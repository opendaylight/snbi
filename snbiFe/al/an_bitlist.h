/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_BITLIST_H__
#define __AN_BITLIST_H__

#include "an_types.h"

int an_bitlist_count(an_bitlist_t *bl);
int an_bitlist_find_first(an_bitlist_t *bl);
int an_bitlist_find_next(an_bitlist_t *bl);
boolean an_bitlist_test(an_bitlist_t *bl, int bit);
void an_bitlist_set(an_bitlist_t *bl, int bit);
void an_bitlist_clearall(an_bitlist_t *bl, int bits, int base);

#endif

