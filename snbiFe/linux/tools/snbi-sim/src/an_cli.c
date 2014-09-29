/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <stdio.h>
#include "libcli.h"
#include <unistd.h>
#include "conf_an.h"
#include "show_an.h"

void cbk1(bool no, int a, char *av[]) {
    printf("\nIn call back 1\n");
}
void cbk2(bool no, int a, char *av[]) {
    printf("\nIn call back 2\n");
}
void quit(bool no, int a, char *av[]) { 
    putchar('\n');
    exit(0); 
}

extern void cli_an_test_init(cli_set_t *s);
void my_periodic ()
{
    if (0 == access("/tmp/test", F_OK)) {
        unlink("/tmp/test");
        printf ("\n file found and removed \n");
        sleep(2);
    }
}
int main (int argc, char *argv[])
{
     cli_set_t *s; /* Create a CLI set */

     /* Initialise the set with a prompt, and 1 mandatory command to exit */
     s = cli_init("snbisim", "quit", quit);

     /* Add a command with no negation */
     cli_insert(s,"hello world", "the Hello world help", cbk1, false);
     /* and one with negation */
     cli_insert(s,"hello", "with a no form ", cbk2, true);

/******************************AN Config CLI's********************************/
     /*Autonomic Start/End CLI...*/
     cli_insert(s,"snbi-start", "Enable Autonomic", an_conf_auton, false);
     cli_insert(s,"snbi-stop", "Disable Autonomic", an_conf_no_auton, false);
     cli_insert(s,"adjvory", "Autonomic adjacency discovery", an_conf_auton_intf, true);

/******************************AN Show CLI's**********************************/
     cli_insert(s,"show autonomic device", "Autonomic Device UDI", an_show_auton, false);
     cli_insert(s,"show autonomic interface", "Autonomic Interfaces", an_show_auton_intf, false);
     cli_insert(s,"show ip interfaces", "IP Interfaces", (cbk_t)an_show_intf, false);
     cli_insert(s,"show process", "Processes", an_show_proc, false);
     cli_insert(s,"show ifinfowalk", "if db walk", (cbk_t)an_walk_if_db, false);
     
    
/**************************** AN Test CLI's ***********************************/
     cli_an_test_init(s);

    /* Handle the command line arguments (-f <file> to read commands from file)*/
     cli_handle_args(s, argc, argv);
     cli_set_periodic(s, my_periodic);
     /* hand over to the interactive read-expand-execute loop */
     cli_loop(s);
    return 0;
} 
