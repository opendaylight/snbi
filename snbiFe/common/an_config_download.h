/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_CONFIG_DOWNLOAD_H__
#define __AN_CONFIG_DOWNLOAD_H__

extern an_timer an_config_download_timer;
void an_conig_download_register_for_events(void);
boolean an_config_download(void);
void an_config_download_reset_timer(void);
#endif
