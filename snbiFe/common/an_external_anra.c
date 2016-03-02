#include <an.h>
#include <string.h>
#include <an_mem.h>
#include <an_if_mgr.h>
#include "an_bs.h"
#include "an_if_linux.h"
#include <olibc_msg_q.h>
#include <an_proc_linux.h>
#include <an_event_mgr_db.h>
#include <an_addr.h>

#define AN_EXTERNAL_ANRA_BS_THYSELF_RETRY_INTERVAL 30*1000

an_v6addr_t registrar_ip_addr = {{{0}}};
an_timer an_external_anra_bs_thyself_retry_timer = {0};
boolean an_external_anra_configured = FALSE;


void
an_trigger_external_ra_connect_msg ()
{
    an_udi_t myudi;
    an_cert_t domain_cert = {};
    an_msg_package *message = NULL;

    if (!an_bs_is_initialized()) {
        an_timer_start(&an_external_anra_bs_thyself_retry_timer,
                   AN_EXTERNAL_ANRA_BS_THYSELF_RETRY_INTERVAL);
        return;
    }

    if (!an_get_udi(&myudi)) {
       DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
               "\nUDI not available");
       an_timer_start(&an_external_anra_bs_thyself_retry_timer,
                   AN_EXTERNAL_ANRA_BS_THYSELF_RETRY_INTERVAL);
        return;
    }

    if (an_get_domain_cert(&domain_cert)) {
        if (domain_cert.valid) {
            // We already have a valid domain cert, no need to retry again.
            return;
        }
    }

    message = an_msg_mgr_get_empty_message_package();
    if (!message) {
        return;
    }

    an_addr_set_from_v6addr(&message->dest, registrar_ip_addr);
    message->ifhndl = 0;

    an_msg_mgr_init_header(message, AN_PROTO_ACP, AN_MSG_NBR_CONNECT);

    if (myudi.len) {
        message->udi.data = (uint8_t *)an_malloc_guard(myudi.len,
                                                       "AN MSG UDI");
        if (!message->udi.data) {
            an_msg_mgr_free_message_package(message);
            return;
        }
        message->udi.len = myudi.len;
        an_memcpy_guard_s(message->udi.data, message->udi.len,
                          myudi.data, myudi.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);
    }

//    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_IF_IPADDR);
    an_msg_mgr_send_message(message);

    an_timer_start(&an_external_anra_bs_thyself_retry_timer,
                   AN_EXTERNAL_ANRA_BS_THYSELF_RETRY_INTERVAL);
    return;
}
void
an_external_anra_bs_thyself_timer_event_handler (void *info_ptr)
{
    if (!an_external_anra_configured) {
        return;
    }
    an_trigger_external_ra_connect_msg();
}

void
an_external_anra_register_for_events ()
{
    an_event_register_consumer(AN_MODULE_EXTERNAL_ANRA,
            AN_EVENT_TIMER_EXTERNAL_ANR_BS_RETRY_EXPIRED,
            an_external_anra_bs_thyself_timer_event_handler);
}

an_v6addr_t
an_external_anra_get_ip ()
{
    return registrar_ip_addr;
}

void
an_external_ra_init (void)
{
    if (an_external_anra_configured) {
        an_timer_stop(&an_external_anra_bs_thyself_retry_timer);
        an_trigger_external_ra_connect_msg();
    }
}

void an_external_anra_set_ip (an_v6addr_t reg_ip)
{   
    if (an_external_anra_configured) {
        printf("\nExternal ANRA already configured");
        return;
    }
    an_external_anra_configured = TRUE;
    memcpy(&registrar_ip_addr, &reg_ip, sizeof(an_v6addr_t));
    an_timer_init(&an_external_anra_bs_thyself_retry_timer,
                  AN_TIMER_TYPE_EXTERNAL_ANRA_BS_THYSELF_RETRY, NULL,
                  FALSE);
    an_trigger_external_ra_connect_msg();
}

boolean
an_external_anra_is_configured ()
{
    return an_external_anra_configured;
}

