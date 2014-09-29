/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "conf_an.h"

void 
an_conf_auton (bool no, int a, char *av[]) {
    printf ("\n*********Starting Autonomic Process************\n");
    an_autonomic_enable(TRUE);
    return;
}

void 
an_conf_no_auton (bool no, int a, char *av[]) {
    an_autonomic_disable(TRUE);
    printf ("\n*************Ending Autonomic Process**********\n");
    return;
}

void
an_conf_auton_intf (bool no, int a, char *av[]) {
    an_if_t ifhndl = 0;
    an_if_info_t *an_if_info = NULL;

// Replace netio0 with av[2] and av[1] resply after taking input from user
    if (no) {
       ifhndl = if_nametoindex("netio0");
    }
    if (!no) {
       ifhndl = if_nametoindex("netio0");
    }
    if (!ifhndl) {
        return;
    }
    an_if_info = an_if_info_db_search(ifhndl, TRUE);
    if (!an_if_info) {
        return;
    }
    
    if (!no) {
/*        if (an_if_is_cfg_autonomic_enabled(an_if_info)) {
        printf("\n [SRK_printf] Autonomic already enabled on interface.. return...!");
           return;
        }
*/
        printf("\n [SRK_printf] Setting interface mode autonomic...!");
        an_if_set_cfg_autonomic_enable(an_if_info, TRUE);
        an_if_autonomic_enable(ifhndl);
    } else if (no) {
        if (!an_if_is_cfg_autonomic_enabled(an_if_info)) {
           return; 
        }
        an_if_autonomic_disable(ifhndl);
        an_if_set_cfg_autonomic_enable(an_if_info, FALSE);
    }

//    return 0;
}
