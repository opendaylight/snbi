/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_types.h>
#include <an_addr.h>
#include <an_logger.h>
#include <an_sudi.h>
#include <an_cert.h>
#include <an_if.h>
#include <an_sign.h>
#include <an_mem.h>
#include <an.h>
#include <an_anra.h>
#include <an_msg_mgr.h>
#include <an_event_mgr.h>
#include <an_bs.h>
#include <an_http_linux.h>


#define ANRA_HTTP_PREFERRED_BUFFER_SIZE 0x1000
#define AN_MIME_TYPE "application/x-masa-request"
#define AN_DEFAULT_RESPONSE_TIMEOUT (30 * ONESEC)
#define AN_DEFAULT_CLIENT_RETRY 5
#define AN_DOMAIN_HASH_LEN 64
#define AN_SCH_MIME_TYPE "text/xml"
#define AN_SOAPACTION "\r\nSOAPAction: \"\""

uint8_t* gettok_script = "/MASAhandler_gettoken.sh";
uint8_t* getaudit_script = "/MASAhandler_getlog.sh";
uint8_t* static_request = "Version .1\nPID:Widget SN:1\n49cf53bfd8f0065a2cf29a8f5379a9d0797bfdf6\n\n";

void an_initialize_post(httpc_app_req_params_t *req_params);
uint8_t *an_masa_prepare_soap_request(masa_msg_type type, an_sign_t sign, an_cert_t sudi, uint32_t* len); 

void
anra_httpc_register (void)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

/*
 * Unregister the http client.
 */

void
anra_httpc_unregister (void)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

/* 
 * Resolve the MASA URL
 */

boolean 
an_masa_resolve_url (uint8_t* url)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return (TRUE);
}

/*
 * Initialize HTTP Post reques
 */
void 
an_initialize_post (httpc_app_req_params_t *req_params)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
    return;
}

/*
 * Add the SOAP header and footer to message so that the SCH server
 * understands our message
 */

uint8_t* 
an_masa_prepare_soap_request (masa_msg_type type, an_sign_t sign,
        an_cert_t sudi, uint32_t* len)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
            return (NULL);
}

void 
an_masa_auth_request_static (masa_msg_type type)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

/*
 * Send the MASA request
 */

void 
an_masa_send_http_request (an_udi_t *udi, masa_msg_type type,
        masa_app_context *masa_context)
{
#ifdef PRINT_STUBS_PRINTF    
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
#endif
        return;
}

