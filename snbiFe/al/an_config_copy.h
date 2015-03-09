/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_CONFIG_COPY_H__
#define __AN_CONFIG_COPY_H__

#include "an_types.h"

int an_config_ifs_parse_config_file_resolved(an_ifs_pathent *src_pathent);
an_ifs_pathent *an_config_ifs_pathent_create(void);
void an_config_ifs_build_path_from_pathent(an_ifs_pathent *src_pathent);
void an_config_ifs_pathent_destroy(an_ifs_pathent *src_pathent);
void an_set_loopback_as_ip_tftp_src_if(boolean set);
void an_config_download_send_message(an_ifs_pathent *src_pathent, ulong value);
void an_config_tftp_set_source_idb(void);
void an_config_tftp_reset_source_idb(void);
void an_config_ifs_build_pathent(an_ifs_pathent *src_pathent, an_config_param_t config_sd_param_global, uint8_t an_file_name[200]);
char* an_config_ifs_get_filename(an_ifs_pathent *src_pathent);
char* an_config_ifs_get_path(an_ifs_pathent *src_pathent);

#endif

