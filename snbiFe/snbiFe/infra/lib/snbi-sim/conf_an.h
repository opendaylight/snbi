/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */



#include "an_event_mgr.h"
#include "an_if_mgr.h"
#include <stdio.h>
#include <unistd.h>
#include "an_types.h"
#include "an_str.h"
#include "libcli.h"

void an_conf_auton(bool no, int a, char *av[]);
void an_conf_no_auton(bool no, int a, char *av[]);
void an_conf_intf_auton(bool no, int a, char *av[]);
void an_conf_intf_no_auton(bool no, int a, char *av[]);
void an_discovery_intf(bool no, int a, char *av[]);
