/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __ANRA_H__
#define __ANRA_H__

#include "an_msg_mgr.h"
#include "an_anra_db.h"

#define AN_CA_SERVER_LEN    128

an_addr_t an_anra_get_registrar_ip(void);

boolean an_anra_is_live(void);

typedef enum anr_ca_type_e_ {
    ANR_NO_CA = 0,
    ANR_LOCAL_CA = 1,
    ANR_EXTERNAL_CA   
} anr_ca_type_e;

typedef enum anr_ca_server_command_e_ {
    ANR_CA_SERVER_COMMAND_CREATE = 1,
} anr_ca_server_command_e;

an_addr_t
an_anra_select_anra_ip_from_srvc_db(an_udi_t udi, boolean firstmax);
uint8_t *
an_anra_get_ca_type_id_to_str(anr_ca_type_e ca_type);
an_mac_addr* an_anra_get_mac_address(void);
an_mac_addr* an_anr_get_servcie_name(void);
boolean an_anra_is_configured(void);
void an_anra_deselect_anra_ip(an_nbr_t *nbr);
void an_anr_register_for_events(void);
void
an_anra_incoming_nbr_connect_message(an_msg_package *message);
void
an_anra_incoming_bs_request_message(an_msg_package *bs_request_msg);
boolean
an_is_valid_ca_type(an_anr_param_t *anr_param);
void an_anra_cs_check(void);
#endif
