/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_EVENT_H__
#define __AN_EVENT_H__

#include "../al/an_types.h"
#include "an.h"
#include "an_nbr_db.h"
#include "an_if_mgr.h"
#include "../al/an_cert.h"
#include "an_event_mgr_db.h"

void an_event_autonomics_init(void);
void an_event_autonomics_uninit(void);
void an_event_registrar_init(void);
void an_event_registrar_uninit(void);
void an_event_system_configured(void);
void an_event_udi_available(void);
void an_event_sudi_available(void);

void an_event_interface_up(an_if_t ifhndl);
void an_event_interface_down(an_if_t ifhndl);
void an_event_interface_erased(an_if_t ifhndl);

void an_event_nbr_link_cleanup_timer_expired(an_nbr_link_context_t *link_ctx);
void an_event_ni_cert_request_timer_expired(void *nbr);

void an_event_hello_refresh_timer_expired(void);

void an_event_nbr_inside_domain(void *nbr);
void an_event_nbr_outside_domain(an_nbr_t *nbr);
void an_event_nbr_add(void *nbr);
void an_event_nbr_link_add(void *nbr, void *nbr_link_data);
void an_event_nbr_params_changed(an_nbr_t *nbr);
void an_event_nbr_refreshed(an_nbr_t *nbr, an_nbr_link_spec_t *link_data);

void an_event_device_bootstrapped(void);
void an_event_device_cert_enroll_success(uchar * cert_der,
                uint16_t cert_len, an_udi_t dest_udi,
                an_addr_t proxy_device, an_iptable_t iptable);
void an_event_anra_bootstrap_retry_timer_expired(void);
void an_event_device_cert_enroll_failed(void);
void an_event_anra_up_locally(void);
void an_event_anra_learnt(an_addr_t ipaddr);
void an_event_anra_reachable(void);
void an_event_anra_shut(void);

void an_event_domain_ca_cert_learnt(void);
void an_event_domain_device_cert_learnt(void);
void an_event_domain_device_cert_renewd(void);
void an_event_domain_device_cert_expired(void);

void an_event_acp_on_nbr_link_created(an_nbr_t *nbr, 
                an_nbr_link_spec_t *nbr_link_data);
void an_event_acp_on_nbr_link_removed(an_nbr_t *nbr, 
                an_nbr_link_spec_t *nbr_link_data);
void an_event_acp_initialized(void);
void an_event_acp_uninitialized(void);
void an_event_acp_negotiate_security_with_nbr_link(an_nbr_t *nbr, 
                               an_nbr_link_spec_t *nbr_link_data);

void an_event_if_autonomic_enable(an_if_t ifhndl);
void an_event_if_autonomic_disable(an_if_t ifhndl);

void an_event_clock_synchronized(void);
void an_event_interface_activated(an_if_info_t *an_if_info);
void an_event_interface_deactivated(an_if_t ifhndl);

void an_event_acp_pre_uninitialization(void);

void an_event_generic_timer_expired(void);
void an_event_my_cert_renew_timer_expired(void);
void an_event_nbr_cert_renew_timer_expired(void *nbr);
void an_event_nbr_cert_in_validity_expired_state(an_nbr_t *nbr);

void an_event_nbr_cert_revalidate_timer_expired(void *nbr);
void an_event_cert_revoke_check_timer_expired(void);

void
an_event_validation_cert_response_obtained(an_cert_validation_result_e status, 
                                           void *device_ctx);

void an_event_registrar_up(void);
void an_event_registrar_shut(void);
void an_event_no_registrar(void);
void an_event_service_received(void *context, int value);
void an_event_service_resolved(void *context, int value);
void an_event_host_resolved(void *context, int value);
#endif
