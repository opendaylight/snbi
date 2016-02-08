#include <an.h>
#include <string.h>
#include <an_mem.h>
#include <an_if_mgr.h>
#include "an_if_linux.h"
#include <olibc_msg_q.h>
#include <an_proc_linux.h>
#include <an_event_mgr_db.h>
#include "an_external_anra.h"
#include <time.h>
#include <pthread.h>
#include "../al/an_misc.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include "../al/an_ipsec.h"
#include "../al/an_cert.h"

extern olibc_pthread_hdl an_pthread_hdl;
extern an_udi_t an_udi_platform_linux;
extern an_timer an_external_anra_bs_thyself_retry_timer;
extern pthread_cond_t      quit_sig_con;
extern pthread_mutex_t     quit_sig_mutex;

olibc_msg_q_hdl an_conf_q_hdl = NULL;

typedef enum an_conf_e_ {
    AN_CONFIG_AUTONOMIC_START,
    AN_CONFIG_AUTONOMIC_STOP,
    AN_CONFIG_UDI,
    AN_CONFIG_INTF_ENABLE,
    AN_CONFIG_INTF_DISABLE,
    AN_CONFIG_REGISTRAR_IP,
    AN_CONFIG_GLOBAL_QUIT
} an_conf_e;

boolean
an_enable_cmd_handler (void)
{
    olibc_retval_t retval;

    if (!an_conf_q_hdl) {
        return FALSE;
    }
    retval = olibc_msg_q_enqueue(an_conf_q_hdl, AN_CONFIG_AUTONOMIC_START, 
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
    retval = olibc_msg_q_enqueue(an_conf_q_hdl, AN_CONFIG_AUTONOMIC_STOP,
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

boolean
an_config_intf_enable_cmd_handler (uint32_t if_index)
{
    olibc_retval_t retval;

    if (!an_conf_q_hdl) {
        return FALSE;
    }
    retval = olibc_msg_q_enqueue(an_conf_q_hdl, AN_CONFIG_INTF_ENABLE,
                                 if_index, NULL);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }
    return TRUE;
}

boolean
an_config_intf_disable_cmd_handler (uint32_t if_index)
{
    olibc_retval_t retval;

    if (!an_conf_q_hdl) {
        return FALSE;
    }
    retval = olibc_msg_q_enqueue(an_conf_q_hdl, AN_CONFIG_INTF_DISABLE,
                                 if_index, NULL);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }

    return TRUE;
}

static void
an_conf_set_udi (olibc_msg_q_event_hdl q_event_hdl)
{
    olibc_retval_t retval;
    void *udi;
    uint32_t udi_str_len = 0;
    an_udi_t udi_str;

    retval = olibc_msg_q_event_get_args(q_event_hdl, NULL, &udi);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to set UDI");
        return;
    }

    memset(&udi_str, 0, sizeof(an_udi_t));

    udi_str_len = strlen(udi);

    an_udi_platform_linux.data = udi;
    an_udi_platform_linux.len = udi_str_len +1;

    udi_str.data = an_malloc(udi_str_len + 1, "Temp UDI string");
    memset(udi_str.data, 0, udi_str_len + 1);
    udi_str.len = an_udi_platform_linux.len;
    strncpy(udi_str.data, udi, udi_str_len);

    an_set_udi(udi_str);
}

static void
an_conf_if_autonomic_enable (olibc_msg_q_event_hdl q_event_hdl)
{
    uint64_t if_index;
    uint32_t if_hndl;
    olibc_retval_t retval;
    an_if_info_t *an_if_info = NULL;

    retval = olibc_msg_q_event_get_args(q_event_hdl, &if_index, NULL);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to enable interface");
        return;
    }

    if_hndl = (uint32_t) if_index;

    an_if_info = an_if_info_db_search(if_hndl, TRUE);

    if (!an_if_info) {
        printf("\nFailed to get ifinfo to enable interface");
        return;
    } 
    
    if (an_if_is_cfg_autonomic_enabled(an_if_info)) { 
        return; 
    }
    an_if_set_cfg_autonomic_enable(an_if_info, TRUE); 
    an_if_autonomic_enable(if_hndl);
}

static void
an_conf_if_autonomic_disable (olibc_msg_q_event_hdl q_event_hdl)
{
    uint64_t if_index;
    uint32_t if_hndl;
    olibc_retval_t retval;
    an_if_info_t *an_if_info = NULL;

    retval = olibc_msg_q_event_get_args(q_event_hdl, &if_index, NULL);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to enable interface");
        return;
    }

    if_hndl = (uint32_t) if_index;

    an_if_info = an_if_info_db_search(if_hndl, TRUE);

    if (!an_if_info) {
        printf("\nFailed to get ifinfo to enable interface");
        return;
    } 
    
    if (!an_if_is_cfg_autonomic_enabled(an_if_info)) { 
        return; 
    }
    an_if_set_cfg_autonomic_enable(an_if_info, FALSE); 
    an_if_autonomic_disable(if_hndl);
}

static void
an_conf_external_register_ip (olibc_msg_q_event_hdl q_event_hdl)
{
    int result;
    char *reg_ip_str;
    an_v6addr_t reg_ip;
    olibc_retval_t retval;

    retval = olibc_msg_q_event_get_args(q_event_hdl, NULL,
                                        (void**) &reg_ip_str);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        printf("\nFailed to get registrar IP");
        an_free(reg_ip_str);
        return ;
    }

    result = inet_pton(AF_INET6, reg_ip_str, (void*)&reg_ip);
    if (result <= 0) {
        if (result == 0) {
            printf("Invalid Registrar IP");
        } else {
            printf("Registrar IP conversion error");
        }
        an_free(reg_ip_str);
        return;
    }

    an_external_anra_set_ip(reg_ip);
    an_free(reg_ip_str);
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
        case AN_CONFIG_AUTONOMIC_START:
            an_event_db_init();
            an_autonomic_enable();
            break;

        case AN_CONFIG_AUTONOMIC_STOP:
            an_autonomic_disable();
	    pthread_mutex_lock(&quit_sig_mutex);	
	    pthread_cond_broadcast(&quit_sig_con);
            pthread_mutex_unlock(&quit_sig_mutex);
            break;

        case AN_CONFIG_UDI:
            an_conf_set_udi(q_event_hdl);
            break;

        case AN_CONFIG_INTF_ENABLE:
            an_conf_if_autonomic_enable(q_event_hdl);
            break;
        case AN_CONFIG_INTF_DISABLE:
            an_conf_if_autonomic_disable(q_event_hdl);
           break;
        case AN_CONFIG_REGISTRAR_IP:
           an_conf_external_register_ip(q_event_hdl);
           break;
        case AN_CONFIG_GLOBAL_QUIT:
           INThandler(0);
           break;
        default:
            printf("\nUnknown type command received");
            return FALSE;
    }
    return TRUE;
}

boolean
an_config_register_ip_cmd_handler (char *ip_str)
{
    int ip_len;
    char *ip = NULL;
    olibc_retval_t retval;

    ip_len = strlen(ip_str);
    ip = an_malloc(ip_len+1, "Registrar IP");
    memset(ip, 0, ip_len+1);
    strncpy(ip, ip_str, ip_len);

    retval = olibc_msg_q_enqueue(an_conf_q_hdl, AN_CONFIG_REGISTRAR_IP,
                                 0, ip);
    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }
    return TRUE;
}
    
boolean
an_system_init_linux ()
{
    olibc_retval_t retval;
    olibc_msg_q_info_t msg_q_info;

    // Initialize rand with time.
    srand(time(NULL));

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

boolean
an_config_global_quit_cmd_handler (void)
{
    INThandler(0);
    return(TRUE);
}

boolean
an_config_global_cleanup_cmd_handler (void)
{
    char an_if_name[100];
    char str_snbi[4] ="snbi";
    olibc_if_event_type_t event_type;
    olibc_if_info_t if_info;
    olibc_if_iterator_filter_t filter;
    olibc_if_iterator_hdl if_iter_hdl;
    olibc_retval_t retval;

    retval = olibc_if_iterator_create(&filter, &if_iter_hdl);

    if (retval != OLIBC_RETVAL_SUCCESS) {
        return FALSE;
    }

    memset(&if_info, 0, sizeof(if_info));
    while (olibc_if_iterator_get_next(if_iter_hdl, &if_info, &event_type) ==
            OLIBC_RETVAL_SUCCESS) {
         if(!strncmp(if_info.if_name,str_snbi,4)){
            snprintf(an_if_name, 100, "%s %s",
                    "sudo ip link del", if_info.if_name);
            system (an_if_name);
         }

        memset(&if_info, 0, sizeof(if_info));
    }
    an_ipsec_profile_uninit();
    an_cert_cleanup();
    return(TRUE);
}
