/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_SERVICE_DISCOVERY_LINUX_H__
#define __AN_SERVICE_DISCOVERY_LINUX_H__

#include "an_cd.h"


/*
 * AN auto discovery macro
 */
#define AN_AUTO_DISC_MAX_DB_SIZE 32
#define AN_AUTO_DISC_MAX_CREDIT 6
#define AN_AUTO_DISC_CREDIT_START 1
#define AN_AUTO_DISC_MIN_CREDIT 0
#define AN_AUTO_DISC_DB_ROW_VALID 1
#define AN_AUTO_DISC_DB_ROW_FREE 0

#define AN_DISC_HOSTNAME_LEN 64

#define AN_AUTO_DISC_INTF_INDEX_NULL 0
#define AN_AUTO_DISC_NO_FLAGS 0x0

#define AN_SYSLOG_SERVICE_TYPE  "syslog"
#define AN_SYSLOG_SERVICE_TYPE_LEN  6
#define AN_SYSLOG_SERVICE_REG_TYPE  "_syslog._udp"

#define AN_AAA_SERVICE_TYPE  "aaa"
#define AN_AAA_SERVICE_TYPE_LEN  3
#define AN_AAA_SERVICE_REG_TYPE  "_aaa._udp"

#define AN_AUTO_DISC_NO_DOMAIN NULL
#define AN_AUTO_DISC_RESEND_INTERVAL 30

an_addr_t anr_sd_param_global;
void an_discover_services(void);
void an_discover_services_deallocate(void);
void an_sd_cfg_global_commands(boolean set);
void an_sd_cfg_if_commands(an_if_t ifhndl, boolean set);

#endif
