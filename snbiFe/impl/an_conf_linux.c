#include <an.h>
#include <string.h>
#include <olibc_msg_q.h>
#include <an_proc_linux.h>
#include <an_event_mgr_db.h>
#include "an_if_linux.h"
#include <an_mem.h>

extern olibc_pthread_hdl an_pthread_hdl;
extern an_udi_t an_udi_platform_linux;

olibc_msg_q_hdl an_conf_q_hdl = NULL;

typedef enum an_conf_e_ {
    AN_AUTONOMIC_START,
    AN_AUTONOMIC_STOP,
    AN_CONFIG_UDI
} an_conf_e;

boolean
an_enable_cmd_handler (void)
{
    olibc_retval_t retval;

    if (!an_conf_q_hdl) {
        return FALSE;
    }
    retval = olibc_msg_q_enqueue(an_conf_q_hdl, AN_AUTONOMIC_START, 
                                 0, NULL);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }
    return TRUE;
}

boolean
an_disable_cmd_handler (void)
{
    olibc_retval_t retval;

    if (!an_conf_q_hdl) {
        return FALSE;
    }
    retval = olibc_msg_q_enqueue(an_conf_q_hdl, AN_AUTONOMIC_STOP,
                                0, NULL);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }
    return TRUE;
}

boolean 
an_config_udi_cmd_handler (char *udi_str)
{
    olibc_retval_t retval;
    int udi_len;
    char *udi = NULL;

    udi_len = strlen(udi_str);
    udi = an_malloc(udi_len+1, "Conf UDI");
    memset(udi, 0, udi_len+1);
    strncpy(udi, udi_str, udi_len);

    if (!an_conf_q_hdl) {
        return FALSE;
    }
    retval = olibc_msg_q_enqueue(an_conf_q_hdl, AN_CONFIG_UDI,
                                 0, udi);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }
    return TRUE;
}

void
an_conf_set_udi (olibc_msg_q_event_hdl q_event_hdl)
{
    olibc_retval_t retval;
    void *udi;

    retval = olibc_msg_q_event_get_args(q_event_hdl, NULL, &udi);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to set UDI");
        return;
    }
    
    an_udi_platform_linux.data = udi;
    an_udi_platform_linux.len = strlen(udi)+1;
    an_set_udi(an_udi_platform_linux);
    return;
}

static boolean 
an_conf_q_cbk (olibc_msg_q_event_hdl q_event_hdl)
{
//    void *msg_ptr;
//    int64_t msg_val;
    uint32_t msg_type;
    olibc_retval_t retval;

    if (!q_event_hdl) {
        return FALSE;
    }

    retval = olibc_msg_q_event_get_type(q_event_hdl, &msg_type);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }

    switch (msg_type) {
        case AN_AUTONOMIC_START:
            an_event_db_init();
            an_autonomic_enable();
            an_if_enable_nd_on_all_intfs();
            break;

        case AN_AUTONOMIC_STOP:
            an_autonomic_disable();
            break;
        case AN_CONFIG_UDI:
            an_conf_set_udi(q_event_hdl);
            break;
        default:
            printf("\nUnknown type command received");
            return FALSE;
    }
    return TRUE;
}

    
boolean
an_system_init_linux ()
{
    olibc_retval_t retval;
    olibc_msg_q_info_t msg_q_info;

    an_proc_init();

    if (!an_pthread_hdl) {
        return FALSE;
    }
    
    memset(&msg_q_info, 0, sizeof(olibc_msg_q_info_t));

    msg_q_info.max_q_len = 10;
    msg_q_info.pthread_hdl = an_pthread_hdl;
    msg_q_info.msg_q_cbk = an_conf_q_cbk;

    retval = olibc_msg_q_create(&an_conf_q_hdl, &msg_q_info);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }
    return TRUE;
}
