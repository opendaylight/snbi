#include <an.h>
#include <string.h>
#include <olibc_msg_q.h>
#include <an_proc_linux.h>
#include <an_event_mgr_db.h>
#include "an_if_linux.h"

extern olibc_pthread_hdl an_pthread_hdl;
olibc_msg_q_hdl an_conf_q_hdl = NULL;

typedef enum an_conf_e_ {
    AN_AUTONOMIC_START,
    AN_AUTONOMIC_STOP
} an_conf_e;

boolean
an_autonomic_start_cmd_handler (void)
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
an_autonomic_stop_cmd_handler (void)
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
