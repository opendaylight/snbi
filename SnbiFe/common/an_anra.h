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

typedef enum anr_config_err_e_ {
    ANR_CONFIG_ERR_NONE = 0,
    ANR_CONFIG_ERR_PENDING,
    ANR_CONFIG_ERR_LIVE,
    ANR_CONFIG_ERR_NOT_LIVE,
    ANR_CONFIG_ERR_NOT_CONFIG,
    ANR_CONFIG_ERR_WHITELIST_FILE,
    ANR_CONFIG_ERR_DEVICE_IN_DOMAIN,
    ANR_CONFIG_ERR_UDI_INVALID,
    ANR_CONFIG_ERR_DEVICE_ACCEPTED,
    ANR_CONFIG_ERR_UNKNOWN,
} anr_config_err_e;

typedef enum anr_ca_server_command_e_ {
    ANR_CA_SERVER_COMMAND_CREATE = 1,
    ANR_CA_SERVER_COMMAND_DELETE,
    ANR_CA_SERVER_COMMAND_SHUT,
    ANR_CA_SERVER_COMMAND_UNSHUT,
} anr_ca_server_command_e;

boolean an_anra_create_whitelist_device_db(uint8_t *whitelist_filename);
void an_anra_configure(uint8_t *domain_id, uint8_t *device_prefix, 
                     uint8_t *whitelist_filename);
void an_anra_unconfigure(void);
void an_anra_incoming_bs_request_message(an_msg_package *message);
void an_anra_incoming_nbr_connect_message(an_msg_package *message);
void an_anra_udi_available(void);
void an_anra_trigger_bs_invite_message(an_udi_t invitee_udi,
                    an_addr_t proxy_addr, an_iptable_t iptable, 
                    an_sign_t *masa_sign);
void an_anra_trigger_bs_reject_message(an_udi_t invitee_udi,
            an_addr_t proxy_addr, an_iptable_t iptable);
void an_anra_generate_domain_hash (char*);
void an_anra_cs_check(void);

const uint8_t *an_anra_get_state_name(void);
boolean an_anra_is_configured(void);
boolean an_anra_is_shut(void);
boolean an_anra_is_live(void);
anr_config_err_e an_anra_config_init(void);
anr_config_err_e an_anra_set_domain_id(uint8_t *domain_id);
anr_config_err_e an_anra_set_device_id_prefix(void *device_id_prefix);
anr_config_err_e an_anra_set_whitelist_filename(void *whitelist_filename);
anr_config_err_e an_anra_allow_quarantine_device(an_udi_t quarantine_udi);
anr_config_err_e an_anra_is_device_accepted(an_udi_t quarantine_udi);
anr_config_err_e an_anra_remove_device_from_whitelist(an_udi_t quarantine_udi);

uint8_t * an_anra_get_domain_id(void);
uint8_t * an_anra_get_device_id_prefix(void);
uint8_t * an_anra_get_whitelist_filename(void);
an_addr_t an_anra_get_registrar_ip(void);
anr_config_err_e an_anra_live(void);
anr_config_err_e an_anra_shut(void);
anr_config_err_e an_anra_delete(void);
extern uint16_t an_routing_ospf;
void an_anra_trigger_bs_invite_message(an_udi_t invitee_udi, 
            an_addr_t proxy_addr, an_iptable_t iptable, an_sign_t* masa_sign);
void an_anra_trigger_bs_reject_message(an_udi_t invitee_udi, 
            an_addr_t proxy_addr, an_iptable_t iptable);
void an_anra_trigger_bs_enroll_quarantine_message(an_udi_t invitee_udi,
            an_addr_t proxy_addr, an_iptable_t iptable);
void an_anra_init(void);
boolean an_anra_write_accepted_device_to_file(an_accepted_device_t *accepted_device);
boolean an_anra_write_quarantine_device_to_file(an_anra_quarantine_device_t *quarantine_device);
an_walk_e an_anra_write_full_quarantine_device_db_cb(an_avl_node_t *node, void *args);
boolean an_anra_write_full_quarantine_device_db_to_file(void);
boolean an_anra_read_whitelist_device_db_from_file(uint8_t *whitelist_filename);
boolean an_anra_read_accepted_device_db_from_file(void);
boolean an_anra_read_quarantine_device_db_from_file(void);
void an_anra_set_local_anra_ip(void);
anr_config_err_e an_anra_set_device_id(uint8_t *device_id);
boolean an_anra_is_device_not_ra_and_bootstrapped(void);
boolean an_anra_is_minimum_config_done(void);
void an_anra_uninit(void);
void an_anra_quarantine_device(an_msg_package *message);
void an_anra_trigger_bs_response_message(an_msg_package *bs_request, an_cert_t *cert);
void an_anra_incoming_nbr_join_message(an_msg_package *message);
void an_anra_incoming_nbr_leave_mesage(an_msg_package *message);
void an_anra_incoming_nbr_lost_mesage(an_msg_package *message);
void an_anra_incoming_nbr_modify_mesage(an_msg_package *message);

void an_anra_delete_pending(void);
void an_anra_live_pending(void);
void an_anra_shut_pending(void);
boolean an_anra_is_live_pen_ca (void);

#endif
