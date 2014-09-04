/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "../al/an_types.h"
#include "../al/an_logger.h"
#include "../al/an_avl.h"
#include "../al/an_if.h"
#include "../al/an_ipv6.h"
#include "../al/an_addr.h"
#include "../al/an_cert.h"
#include "../al/an_mem.h"
#include "an_nbr_db.h"
#include "an.h"
#include "an_cnp.h"

//extern typedef struct cs_cfg;
//extern cs_cfg* crypto_cs_new_cfg(uchar *);

#if 0
uint8_t 
an_itoa_len (uint8_t num)
{
    uint16_t i = 0, len = 0, digit = 0, units = 0, places = 0;

    units = 1;
    places = 10;

    for (i = 0; i < 3; i++, units *= 10, places *= 10)
    {
        digit = (num%(places))/(units);
        if (digit) {
            len = i+1;
        }
    }
    return (len);
}

/* Caller should allocate the string */
void
an_itoa (uint8_t num, uint8_t *str)
{
    uint16_t i = 0, len = 0, digit = 0, units = 0, places = 0;

    if (!str) {
        return;
    }    

    units = 1;
    places = 10;

    len = an_itoa_len(num);
    str[len] = '\0';
    for (i = 0; i < len; i++, units *= 10, places *= 10)
    {
        digit = (num%(places))/(units);
        str[len-i-1] = digit + 48;
    }
}

void
an_concat_str_with_num (uint8_t *prefix_str, uint8_t suffix_num, uint8_t **str)
{
    uint8_t *suffix_str = NULL;
    uint8_t prefix_len = 0, suffix_len = 0;

   prefix_len = an_strlen(prefix_str);
    suffix_len = an_itoa_len(suffix_num);
    suffix_str = (uint8_t*)malloc(sizeof(uint8_t)*(suffix_len+1));
    an_itoa(suffix_num, suffix_str);

    memcpy(*str, prefix_str, prefix_len);
    memcpy(*str + prefix_len, suffix_str, suffix_len+1);

    free(suffix_str);
}
#endif

void an_new (void)
{
    return;
}

/*
extern https_api_status_t
       http_cfg_set_server_status(server_status, boolean);
cs_cfg *an_cs_cfg = NULL;

void
an_start_cert_server (uint8_t *ca_server_label)
{
    http_cfg_set_server_status(HTTP_SERVER_ENABLED, FALSE);
    an_log(AN_LOG_ANRA, "\nEnabled ip http server");
    
    if (an_cs_cfg) {
        an_log(AN_LOG_ANRA, "\nanra certificate server is already up");
        return;
    }

    cs_init();
    an_cs_cfg = crypto_cs_new_cfg(ca_server_label);
    an_cs_cfg->flags |= FLAG_GRANT_AUTO;
    an_cs_cfg->flags &= ~FLAG_GRANT_NONE;
    an_cs_cfg->flags &= ~FLAG_GRANT_RAAUTO;
    
    an_log(AN_LOG_ANRA, "\nstarted anra certificate server with label %s", 
           ca_server_label);
}

void
an_stop_cert_server (uint8_t *ca_server_label)
{
    http_cfg_set_server_status(HTTP_SERVER_DISABLED, FALSE);
    an_log(AN_LOG_ANRA, "\nDisabled ip http server");

    if (!an_cs_cfg) {
        an_log(AN_LOG_ANRA, "\nanra certificate server is already down");
        return;
    }

    crypto_cs_input_handler(an_cs_cfg, &CS_REMOVE_SERVER, 0);
    crypto_cs_free_cfg(an_cs_cfg);
    an_cs_cfg = NULL;
    
    an_log(AN_LOG_ANRA, "\nstopped anra certificate server with label %s", 
           ca_server_label);
}
*/

