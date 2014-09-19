/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */



#include "an_event_mgr.h"
#include "an_if_mgr.h"
#include "an_types.h"
#include <stdio.h>
#include <unistd.h>
#include "libcli.h"
#include "/usr/include/uuid/uuid.h"
#include <uuid/uuid.h>

void an_show_auton(bool no, int a, char *av[]);
void an_show_auton_intf(bool no, int a, char *av[]);
void an_show_intf(bool no, int a, char *av[]);
void an_show_proc(bool no, int a, char *av[]);
void an_walk_if_db(bool no, int a, char *av[]);
