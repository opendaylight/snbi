/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include "an_anra.h"
#include "../al/an_types.h"
#include "../al/an_addr.h"
#include "../al/an_logger.h"
#include "an_srvc_db.h"

uint8_t *an_anr_service_name;
an_timer an_anra_bs_thyself_retry_timer = {0};

typedef enum anr_info_state_e_ {
    ANR_INFO_STATE_NONE             =   0,
} anr_info_state_e;

typedef struct anra_info_t_ {
    anr_info_state_e state;
    anr_ca_type_e ca_type;
    uint8_t *ca_url;
    an_addr_t registrar_ip;
    an_mac_addr *macaddress;
} anra_info_t;

anra_info_t anra_info = {};

an_addr_t
an_anra_get_registrar_ip (void)
{
    return (AN_ADDR_ZERO);
}

boolean
an_anra_is_live (void)
{
    return (FALSE);
}

static uint8_t *anr_ca_name_str[] = {
    "NO CA",
    "IOS CA",
    "IOS RA",
};

uint8_t *
an_anra_get_ca_type_name (void)
{
    return (anr_ca_name_str[anra_info.ca_type]);
}

an_addr_t
an_anra_select_anra_ip_from_srvc_db (an_udi_t udi, boolean firstmax)
{
    an_addr_t anr_address = AN_ADDR_ZERO;

    boolean result = FALSE;

    result = an_srvc_find_anr_service(udi, firstmax);
    if (result == FALSE) {
       DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_SEVERE, NULL,
            "\n %s ANR service is unavailable", an_srvc_event);
       anr_sd_param_global.address = AN_ADDR_ZERO;
    } else {
       DEBUG_AN_LOG(AN_LOG_SRVC_EVENT, AN_DEBUG_MODERATE, NULL,
            "%s New ANR service is at %s",an_srvc_event,
            an_addr_get_string(&anr_sd_param_global.address));
    }
    anr_address = anr_sd_param_global.address;

    return (anr_address);
}

an_mac_addr*
an_anra_get_mac_address (void)
{
    return (anra_info.macaddress);
}

uint8_t *
an_anra_get_ca_type_id_to_str (anr_ca_type_e ca_type)
{
    return (anr_ca_name_str[ca_type]);
}

an_mac_addr*
an_anr_get_servcie_name (void)
{
    return (an_anr_service_name);
}

boolean
an_anra_is_configured (void)
{
    return (anra_info.state != ANR_INFO_STATE_NONE);
}

void
an_anra_deselect_anra_ip (an_nbr_t *nbr)
{
   if (nbr == NULL) {
       return;
   }
   nbr->selected_anr_addr = AN_ADDR_ZERO;
   nbr->selected_anr_reference_time = 0;
}

void an_anr_register_for_events (void)
{    
    return;
}

void
an_anra_incoming_nbr_connect_message (an_msg_package *message)
{
    return;
}

void
an_anra_incoming_bs_request_message (an_msg_package *bs_request_msg)
{
    return;
}

boolean
an_is_valid_ca_type (an_anr_param_t *anr_param)
{
    if (!an_strcmp(an_anra_get_ca_type_id_to_str(ANR_LOCAL_CA), anr_param->ca_type)
        || !an_strcmp(an_anra_get_ca_type_id_to_str(ANR_EXTERNAL_CA), anr_param->ca_type)) {
        return (TRUE);
    } else {
        return (FALSE);
    }
}

void
an_anra_cs_check (void)
{
    return;
}
