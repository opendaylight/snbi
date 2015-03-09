/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_SYSLOG_H__
#define __AN_SYSLOG_H__
#include "../al/an_logger.h"

extern an_addr_t *hstaddran;
extern char *discriminator;
extern char *facility_name;
extern int sev_includes_drops_flag;
extern int fac_includes_drops_flag;
extern boolean an_syslog_server_set;
void an_syslog_init(void);
void an_syslog_uninit(void);
void an_syslog(an_syslog_msg_e type,...);
void an_syslog_connect(void);
void an_syslog_disconnect(void);
void an_syslog_set_server_address(an_addr_t *syslog_addr, boolean service_add);
void an_syslog_config_host(an_addr_t *hstaddran, char *an_vrf_name,
                            an_idbtype *an_idb, char *discriminator);
void an_syslog_delete_host(an_addr_t *hstaddran, char *an_vrf_name);

void an_syslog_create_an_discriminator(void);
void an_syslog_delete_an_discriminator(void);
#endif
