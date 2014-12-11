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

#define AN_ANRA_CS_CHECK_INTERVAL 15*1000
#define AN_ANRA_BS_THYSELF_RETRY_INTERVAL 60*1000
#define AN_REGISTRAR_DEFAULT_DB_URL "nvram:"

/* These file identifiers are useful when messages are sent across processes,
 * which will help in writing a device data to accepted file or quarantine file
 */   
#define AN_ACCEPTED_FILE_IDENTIFIER 1 
#define AN_QUARANTINE_FILE_IDENTIFIER 2

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
  //  ANR_CONFIG_ERR_HOSTNAME_LEN,
  //  ANR_CONFIG_ERR_HOSTNAME_ILLEGAL,
    ANR_CONFIG_ERR_UNKNOWN,
} anr_config_err_e;

typedef enum anr_ca_server_command_e_ {
    ANR_CA_SERVER_COMMAND_CREATE = 1,
    ANR_CA_SERVER_COMMAND_DELETE,
    ANR_CA_SERVER_COMMAND_SHUT,
    ANR_CA_SERVER_COMMAND_UNSHUT,
} anr_ca_server_command_e;

typedef enum anr_ca_type_e_ {
    ANR_NO_CA = 0,
    ANR_LOCAL_CA = 1,
    ANR_EXTERNAL_CA               
} anr_ca_type_e;

#define AN_DOMAIN_ID_MAX_LEN 64
#define AN_CA_SERVER_LEN    128
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
boolean an_anra_bootstrap_thyself(void);
boolean an_anra_is_device_ra_and_not_bootstraped(void);
anr_config_err_e an_anra_config_init(void);
anr_config_err_e an_anra_set_domain_id(uint8_t *domain_id);
anr_config_err_e an_anra_set_db_url(uint8_t *db_url);
anr_config_err_e an_anra_set_ca_url(uint8_t *ca_url);
anr_config_err_e an_anra_set_ca_vrf(uint8_t *vrf_name);
anr_config_err_e an_anra_set_ca_type(anr_ca_type_e ca_type);
anr_config_err_e an_anra_set_device_id_prefix(uint8_t *device_id_prefix);
anr_config_err_e an_anra_set_whitelist_filename(void *whitelist_filename);
boolean an_anra_is_external_ca(void);
boolean an_anra_is_local_ca(void);
boolean an_anra_is_ca_configured(void);
anr_config_err_e an_anra_allow_quarantine_device(an_udi_t quarantine_udi);
anr_config_err_e an_anra_is_device_accepted(an_udi_t quarantine_udi);
anr_config_err_e an_anra_remove_device_from_whitelist(an_udi_t quarantine_udi);
anr_config_err_e an_anra_set_mac_address(an_mac_addr *mac_address);
uint8_t * an_anra_get_domain_id(void);
uint8_t * an_anra_get_db_url(void);
uint8_t * an_anra_get_ca_url(void);
uint8_t * an_anra_get_device_id_prefix(void);
uint8_t * an_anra_get_whitelist_filename(void);
uint8_t * an_anra_get_ca_vrf(void);
anr_ca_type_e an_anra_get_ca_type(void);
uint8_t *an_anra_get_ca_type_name (void);
uint8_t *an_anra_get_ca_type_id_to_str(anr_ca_type_e ca_type);
boolean an_is_valid_ca_type(an_anr_param_t *anr_param);
an_addr_t an_anra_get_registrar_ip(void);
anr_config_err_e an_anra_live(void);
anr_config_err_e an_anra_shut(void);
anr_config_err_e an_anra_delete(void);
extern uint16_t an_routing_ospf;

boolean an_anra_is_db_url_not_default(void);

void an_anra_delete_pending(void);
void an_anra_live_pending(void);
void an_anra_shut_pending(void);
boolean an_anra_is_live_pen_ca (void);
boolean an_anra_write_accepted_device_to_file(an_accepted_device_t *accepted_device);
boolean an_anra_write_quarantine_device_to_file(an_anra_quarantine_device_t *quarantine_device);
boolean an_anra_read_accepted_device_db_from_file (void);
boolean an_anra_read_quarantine_device_db_from_file (void);
void an_anr_copy_files(void);
void an_anra_notify_cert_enrollment_done(an_cert_t *device_cert, 
                            an_udi_t dest_udi, an_addr_t proxy_device, 
                            an_iptable_t iptable);

an_mac_addr* an_anra_get_mac_address(void);
an_addr_t an_anr_get_ip_from_srvc_db(void);
anr_config_err_e an_anr_set_service_name(an_mac_addr *mac_address);
an_mac_addr* an_anr_get_servcie_name(void);
#endif
