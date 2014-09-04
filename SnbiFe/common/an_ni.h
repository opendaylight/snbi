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

boolean an_ni_validate_nbrs(void);
boolean an_ni_cert_request(an_nbr_t *nbr);
boolean an_ni_cert_request_retry(an_nbr_t *nbr);
boolean an_ni_incoming_cert_request(an_msg_package *message);
boolean an_ni_incoming_cert_response(an_msg_package *message);

boolean an_ni_is_nbr_inside(an_nbr_t *nbr);
boolean an_ni_is_nbr_outside(an_nbr_t *nbr);
uint8_t *an_ni_get_state_name(an_nbr_t *nbr);

boolean an_cert_equal(const an_cert_t cert1, const an_cert_t cert2);
#endif
