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
void an_discover_services_deallocate(void);
void an_sd_cfg_global_commands(boolean set);
void an_discover_services(void);
void an_thread_check_and_suspend(void);
void an_handle_interface_up(an_if_t ifhndl);
void an_handle_interface_down(an_if_t ifhndl);
void an_handle_interface_erased(an_if_t ifhndl);
void an_handle_registrar_up(void);
void an_handle_registrar_shut(void);
void an_handle_no_registrar(void);
void an_sd_cfg_if_commands(an_if_t ifhndl, boolean set);
void an_dm_message_send(uint32 message_type, uint32 message_arg);
void an_create_regsiter_watched_queues(void);
void an_create_register_watched_boolean(void);
void an_deregister_watched_queues(void);
boolean an_is_platform_type_whales2(void);
boolean an_is_active_rp (void);

#endif
