/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_MISC_H__
#define __AN_MISC_H__

#include "../common/an_anra.h"
#include "../common/an_if_mgr.h"

#define AN_VLAN_START     4000
#define AN_NO_INNER_VLAN_TAG 0
#define AN_TEMP_INNER_TAG 4094
#define AN_MAX_WAIT_COUNT_BEFORE_SETUP_ABORT 10

extern an_watched_boolean *an_wb_node_discovered;
extern an_watched_boolean *an_setup_done_by_user;
extern an_watched_boolean *an_manual_config_detected; 

typedef enum an_proc_messages_ {
    AN_PMSG_IF_DOWN,
    AN_PMSG_IF_UP,
    AN_PMSG_IF_ERASED,
    AN_PMSG_ANRA_UP,
    AN_PMSG_ANRA_SHUT_PENDING,
    AN_PMSG_ANRA_NO_REGISTRAR,
    AN_PMSG_LOCAL_FILE_WRITE,
    AN_PMSG_COPY_TO_STANDBY,
    AN_PMSG_SERVICE_RECEIVED,
    AN_PMSG_SERVICE_RESOLVED,
    AN_PMSG_HOST_RESOLVED,
    AN_PMSG_CONFIG_DOWNLOAD,
    AN_PMSG_CONFIG_DNLD_STATUS,
    AN_PMSG_MAX,
} an_proc_messages;


#include "../common/an_srvc_db.h"
#include "an_types.h"

#define AN_IPSEC_MSG_ID 0x0
#define AN_SPI 265
#define an_debug_acp 1
#define MAX_PID_LEN  18

typedef enum an_platform_types_ {
   AN_PLATFORM_TYPE_UNKNOWN,
   AN_PLATFORM_TYPE_PURA_NON_AGORA,
   AN_PLATFORM_TYPE_PURA_AGORA,
   AN_PLATFORM_TYPE_WHALES1,
   AN_PLATFORM_TYPE_WHALES2,
   AN_PLATFORM_TYPE_RUDY,
   AN_PLATFORM_TYPE_BENI,
} an_platform_types;

boolean an_ipsec_ss_open_close(char an_ipsec_policy[31], an_v6addr_t localip, an_v6addr_t remoteip,
                        ushort localport, ushort remoteport,
                        int prot, an_if_t ifhndl, boolean openflag);
void an_ipsec_init_ss_api_layer(void);
boolean an_ipsec_create_ipsec_policy(int spi, char* an_acp_key, char an_ipsec_policy[31]);
void an_ipsec_ss_api_listen_start(char an_ipsec_policy[31], boolean flag);

void an_hostname_set(uint8_t *name);
void an_config_save(void);

boolean an_system_is_configured(void);
uint64_t an_pow(uint32_t num, uint32_t pow);

void an_platform_specific_init(void);
void an_platform_specific_uninit(void);
boolean an_process_time_exceeded(void);
void an_process_suspend(void);
void an_process_may_suspend(void);
void an_anra_cfg_ca_server(anr_ca_server_command_e command);
//void an_discover_services_deallocate(void);
void an_sd_cfg_global_commands(boolean set);
//void an_discover_services(void);
void an_thread_check_and_suspend(void);
void an_handle_interface_up(an_if_t ifhndl);
void an_handle_interface_down(an_if_t ifhndl);
void an_handle_interface_erased(an_if_t ifhndl);
void an_handle_registrar_up(void);
void an_handle_registrar_shut(void);
void an_handle_no_registrar(void);
void an_sd_cfg_if_commands(an_if_t ifhndl, boolean set);
void an_process_send_message (an_thread_t pid, const char *key, ulong message_num, void *pointer, ulong message_arg);
void an_create_regsiter_watched_queues(void);
void an_deregister_watched_queues(void);
boolean an_is_platform_type_whales2(void);
boolean an_is_platform_type_pura(void);
boolean an_is_active_rp(void);
boolean an_is_startup_config_exists(void);
boolean an_setup_running(void);

void an_process_call(void );
void an_process_call_shut(void);
void an_process_call_no_registrar(uint32_t value_chk);
void an_service_clear_entry(an_service_type_t an_service_type);
boolean an_cd_send_periodic_untagged_probe_cb(an_avl_node_t *node, void *data);
boolean an_if_check_type_layer3(an_if_t ifhndl);
an_if_type_e an_if_set_and_get_type(an_if_t ifhndl, an_if_type_e an_if_type,
                                                             boolean force);
void an_mdns_anra_service_add(an_addr_t anra_ip, an_if_t int_index, uint8_t *l2_mac); 
//void an_service_reflect_on_interfaces(an_address_saved_context_t *saved_context);
void an_clear_service_info_db(void);
boolean an_is_system_configured_completely(void);
void an_dm_init(void);
void an_init_helper_process(void);
boolean an_is_manual_config_detected(void);
boolean an_is_node_discovered(void);
boolean an_is_setup_max_wait_reached(void);
void an_main_loop(void);
void an_discover_services_deallocate(an_if_t ifhndl);
void an_sd_cfg_global_commands(boolean set);
void an_sd_cfg_if_commands(an_if_t ifhndl, boolean set);
void an_service_reflect_on_interfaces(an_srvc_srv_ctx_t *saved_context);
void an_clear_service_info_db(void);
void an_host_resolve (an_srvc_host_t *host_data, an_if_t ifIndex);
void an_service_resolve (uint8_t *serName, uint8_t *regType, uint8_t *domain,
                        an_srvc_srv_t *srv_data);
boolean an_service_announce (an_service_type_t service_type, uint8_t *serName,
                an_addr_t service_ip, void *service_param, an_if_t int_index);
boolean an_service_withdraw (an_service_type_t service_type, uint8_t *serName,
            an_if_t int_index);
boolean an_l2_check_intf_is_autonomic_possible(an_if_t ifhndl);            
uint32_t an_rand(void);
void an_discover_syslog_service(an_if_t ifhndl);
void an_discover_anr_service(an_if_t ifhndl);
void an_discover_aaa_service(an_if_t ifhndl);
void an_discover_config_service(an_if_t ifhndl);
void an_mdns_io_set_rate_limit_rate (uint32_t packet_num);
boolean an_get_device_base_mac_addr(an_mac_addr chassis_mac[AN_IEEEBYTES]);

//boolean an_get_device_hostname(uint8_t *name, uint8_t namelen);
//boolean an_get_device_system_hostname(uint8_t *name);
an_platform_types an_get_platform_type(void);
boolean an_platform_is_media_type_supported(void);
#endif
