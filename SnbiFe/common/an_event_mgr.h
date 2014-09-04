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

void an_event_autonomics_init(void);
void an_event_autonomics_uninit(boolean flag);
void an_event_registrar_init(void);
void an_event_registrar_uninit(void);
void an_event_system_configured(void);
void an_event_udi_available(void);
void an_event_sudi_available(void);

void an_event_interface_up(an_if_t ifhndl);
void an_event_interface_down(an_if_t ifhndl);
void an_event_interface_erased(an_if_t ifhndl);

void an_event_nbr_link_cleanup_timer_expired(an_nbr_link_context_t *link_ctx);
void an_event_ni_cert_request_timer_expired(an_nbr_t *nbr);

void an_event_hello_refresh_timer_expired(void);

void an_event_nbr_inside_domain(an_nbr_t *nbr);
void an_event_nbr_outside_domain(an_nbr_t *nbr);
void an_event_nbr_add(an_nbr_t *nbr);
void an_event_nbr_lost(an_nbr_t *nbr);
void an_event_nbr_link_lost(an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data);
void an_event_nbr_link_add(an_nbr_t *nbr, an_nbr_link_spec_t *nbr_link_data);
void an_event_remove_and_free_nbr(an_nbr_t *nbr);
void an_event_nbr_params_changed(an_nbr_t *nbr, an_msg_interest_e changed);
void an_event_nbr_refreshed(an_nbr_t *nbr);
void an_event_device_bootstrapped(void);
void an_event_nbr_domain_cert_validated(an_nbr_t *nbr,boolean result);

void an_event_anra_up_locally(void);
void an_event_anra_learnt(an_addr_t ipaddr);
void an_event_anra_reachable(void);
void an_event_anra_shut(void);

void an_event_domain_ca_cert_learnt(void);
void an_event_domain_device_cert_learnt(void);

void an_event_acp_to_nbr_created(an_nbr_t *nbr);
void an_event_acp_to_nbr_removed(an_nbr_t *nbr);
void an_event_acp_initialized(void);
void an_event_acp_uninitialized(void);
void an_event_acp_negotiate_security_with_nbr_link(an_nbr_t *nbr, 
                               an_nbr_link_spec_t *nbr_link_data);

void an_event_if_autonomic_enable(an_if_t ifhndl);
void an_event_if_autonomic_disable(an_if_t ifhndl);

void an_event_clock_synchronized(void);
void an_event_interface_activated(an_if_t ifhndl);
void an_event_interface_deactivated(an_if_t ifhndl);

void an_event_acp_pre_uninitialization(void);

void an_sudi_uninit(void);
void an_sudi_init(void);
void an_addr_generator_init(void);

void an_event_generic_timer_expired(void);

void an_event_registrar_up(void);
void an_event_registrar_shut(void);
void an_event_no_registrar(void);
#endif
