/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_NI_H__
#define __AN_NI_H__

#include "an_nbr_db.h"
#include "an_msg_mgr.h"

#define AN_NI_CERT_REQUEST_INTERVAL (40*1000)
#define AN_NI_CERT_REVALIDATE_INTERVAL (3*60*1000)
#define AN_MY_CERT_IMPORT_BUFFER_TIME_SEC 180 // 0 min
#define AN_NBR_CERT_IMPORT_BUFFER_TIME_SEC 180 // 0 min
#define AN_MAX_ALLOWED_TIME_NBR_IN_EXPIRED_STATE (15*60) //15 min
#define AN_MAX_POLL_FOR_NBR_CERT 11
#define AN_MAX_NI_RETRY_ATTEMPT 4

typedef struct an_ni_validate_context_t_ {
    an_udi_t save_udi;
} an_ni_validate_context_t; 

boolean an_ni_validate_nbrs(void);
boolean an_ni_validate_with_crl_nbrs(void);
boolean an_ni_validate_expired_nbrs(void);

boolean an_ni_cert_request(an_nbr_t *nbr);
boolean an_ni_cert_request_retry(an_nbr_t *nbr);
boolean an_ni_incoming_cert_request(an_msg_package *message);
boolean an_ni_incoming_cert_response(an_msg_package *message);
void an_ni_cert_revalidate_timer_start(an_nbr_t *nbr);
void an_ni_cert_revalidate_timer_stop(an_nbr_t *nbr);
void an_ni_validate(an_nbr_t *nbr);
void an_ni_validate_with_crl(an_nbr_t *nbr);

boolean an_ni_is_nbr_inside(an_nbr_t *nbr);
boolean an_ni_is_nbr_outside(an_nbr_t *nbr);
uint8_t *an_ni_get_state_name(an_nbr_t *nbr);
void an_ni_start_nbr_cert_expire_timer(an_nbr_t *nbr);
boolean an_ni_set_state(an_nbr_t *nbr, an_ni_state_e state);
void an_ni_set_validation_result(an_nbr_t *nbr, an_cert_validation_result_e result);
boolean an_ni_is_nbr_revoked(an_nbr_t *nbr);
boolean an_ni_is_nbr_expired(an_nbr_t *nbr);
void an_ni_update_nbr_cert_validation_result(
            an_cert_validation_result_e result, an_nbr_t *nbr);
void an_ni_validation_cert_response_obtained(an_cert_validation_result_e status,
                                            void *device_ctx);
#endif
