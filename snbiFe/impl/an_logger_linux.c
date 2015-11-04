/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include <an_logger.h>
#include <an_misc.h>
//#include <an_parse_dummy.h>
#include <an_tlv.h>
#include <an_file.h>
#include <an_file_linux.h>
#include <an_syslog.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#define AN_LOG_FLAG_FROM_LOG_CFG(cfg) (an_pow(2, cfg - 1))
int an_debug_map[AN_LOG_ALL_ALL] = {
                        AN_DEBUG_MAX, AN_DEBUG_MAX, AN_DEBUG_MAX, AN_DEBUG_MAX,
                        AN_DEBUG_MAX, AN_DEBUG_MAX, AN_DEBUG_MAX, AN_DEBUG_MAX,
                        AN_DEBUG_MAX, AN_DEBUG_MAX, AN_DEBUG_MAX, AN_DEBUG_MAX,
                        AN_DEBUG_MAX, AN_DEBUG_MAX, AN_DEBUG_MAX, AN_DEBUG_MAX,
                        AN_DEBUG_MAX, AN_DEBUG_MAX, AN_DEBUG_MAX, AN_DEBUG_MAX,
                        AN_DEBUG_MAX, AN_DEBUG_MAX, AN_DEBUG_MAX
                       };

extern an_file_api_ret_enum 
an_file_write_fs(an_file_descr_t fd, const char *fmt, va_list args);

an_file_descr_t log_fd_ = STDOUT_FILENO;

an_log_type AN_LOG_NONE;
an_log_type AN_LOG_ND;
an_log_type AN_LOG_CD;
an_log_type AN_LOG_NI;
an_log_type AN_LOG_BS;
an_log_type AN_LOG_ACP;
an_log_type AN_LOG_MESSAGE;
an_log_type AN_LOG_ANRA;
an_log_type AN_LOG_EVENT;
an_log_type AN_LOG_SUDI;
an_log_type AN_LOG_TLV;
an_log_type AN_LOG_MSG_MGR;
an_log_type AN_LOG_IDP;
an_log_type AN_LOG_IF;
an_log_type AN_LOG_ERR;
an_log_type AN_LOG_DB;
an_log_type AN_LOG_IP;
an_log_type AN_LOG_PAK;
an_log_type AN_LOG_TIMER;
an_log_type AN_LOG_AVL;
an_log_type AN_LOG_SIGN;
an_log_type AN_LOG_CERT;
an_log_type AN_LOG_CLI;
an_log_type AN_LOG_MASA;
an_log_type AN_LOG_MEM;
an_log_type AN_LOG_SRVC;
an_log_type AN_LOG_TOPO;
an_log_type AN_LOG_AAA;
an_log_type AN_LOG_LIST;
an_log_type AN_LOG_CNP;
an_log_type AN_LOG_NBR_LINK;
an_log_type AN_LOG_NTP;
an_log_type AN_LOG_FILE;
an_log_type AN_LOG_INTENT;
an_log_type AN_LOG_ALL;

uint64_t an_log_flag = 0;
static boolean an_logger_initialized = FALSE;

const uint8_t * an_nd_event = "AN: ND_EVENT - ";
const uint8_t * an_nd_pak = "AN: ND_PACKET - ";
const uint8_t * an_nd_db = "AN: ND_DB - ";
const uint8_t * an_bs_event = "AN: BS_EVENT - ";
const uint8_t * an_bs_pak = "AN: BS_PACKET - ";
const uint8_t * an_ra_event = "AN: REGISTRAR_EVENT - ";
const uint8_t * an_ra_db = "AN: REGISTRAR_DB - ";
const uint8_t * an_srvc_event = "AN: SRVC_EVENT - ";
const uint8_t * an_srvc_pak = "AN: SRVC_PACKET - ";
const uint8_t * an_srvc_aaa = "AN: SRVC_AAA - ";
const uint8_t * an_srvc_ntp = "AN: SRVC_NTP - ";
const uint8_t * an_srvc_syslog = "AN: SRVC_SYSLOG - ";
const uint8_t * an_srvc_idp = "AN: SRVC_IDP - ";

const uint8_t * an_cd_event = "AN: CD_EVENT - ";
const uint8_t * an_cd_pak = "AN: CD_PACKET - ";
const uint8_t * an_cd_db = "AN: CD_DB - ";

const uint8_t * an_timer_prefix = "AN: TIMER - ";
const uint8_t * an_nd_prefix = "AN: ND - ";
const uint8_t * an_cd_prefix = "AN: CD - ";
const uint8_t * an_tlv_prefix = "AN: TLV - ";
const uint8_t * an_srvc_prefix = "AN: SRVC - ";
const uint8_t * an_msg_mgr_prefix = "AN: MSG_MGR - ";
const uint8_t * an_nbr_link_prefix = "AN: NBR_LINK - ";
const uint8_t * an_topo_prefix = "AN: TDP - ";
const uint8_t * an_pak_prefix = "AN: TUNNEL - ";
const uint8_t * an_ni_prefix = "AN: NI - ";
const uint8_t * an_srvc_config = "AN: SRVC_CONFIG - ";

const uint8_t *an_log_lev_str [] = {
    "Info",
    "Moderate",
    "Severe",
    "Max",
};

const uint8_t *an_log_cfg_string [] = {
    "None",
    "AN Nbr Discovery Events",
    "AN Nbr Discovery Packets",
    "AN Nbr Discovery DB",
    "AN Nbr Discovery All",

    "AN Bootstrap Events",
    "AN Bootstrap Packets",
    "AN Bootstrap All",

    "AN Registrar Events",
    "AN Registrar DB",
    "AN Registrar All",

    "AN Services Events",
    "AN Services Packets",
    "AN Services AAA",
    "AN Services NTP",
    "AN Services SYSLOG",
    "AN Services IDP",
    "AN Services Topology",
    "AN Services CONFIG",
    "AN Services All",

    "AN Intent Events",
    "AN Intent Packets",
    "AN Intent All",

    "AN INfra Events",
};

static const uint8_t *an_log_string [] = {

    "AN: NONCE - ",

    "AN: ND_EVENT - ",
    "AN: ND_PACKET - ",
    "AN: ND_DB - ",
    "AN: ND_ALL - ",

    "AN: BS_EVENT - ",
    "AN: BS_PACKET - ",
    "AN: BS_ALL - ",

    "AN: REGISTRAR_EVENT - ",
    "AN: REGISTRAR_DB - ",
    "AN: REGISTRAR_ALL - ",

    "AN: SRVC_EVENT - ",
    "AN: SRVC_PACKET - ",
    "AN: SRVC_AAA - ",
    "AN: SRVC_NTP - ",
    "AN: SRVC_SYSLOG - ",
    "AN: SRVC_IDP - ",
    "AN: SRVC_ALL - ",

    "AN: ALL_ALL - ",
};

const uint8_t * an_get_log_str(an_log_type_e log)
{
    return (an_log_string[log]);
}

static void an_log_all (boolean sense)
{
    if (sense) {
        an_log_start(AN_LOG_CFG_ALL);
    } else if (!sense) {
        an_log_stop(AN_LOG_CFG_ALL);
    }
}

void vbuginf(const char *fmt, va_list args) 
{
    an_file_api_ret_enum retval;

   if (!an_file_descr_is_valid(log_fd_)) {
       printf("Invalid filedescriptor in vbuginf %d\n", log_fd_);
       return;
    }

    retval = an_file_write_fs(log_fd_, fmt, args);
    if (retval != AN_FILE_API_SUCCESS) {
        printf("Failed to write to write to fd %d\n", log_fd_);
        return;
    }
    return;
}

static boolean
an_logger_is_initialized (void)
{
    return (an_logger_initialized);
}

void an_logger_init (void)
{
    if (an_logger_is_initialized()) {
        return;
    }
    AN_LOG_NONE         =   0;
    AN_LOG_ND           =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_ND);
    AN_LOG_CD           =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_CD);
    AN_LOG_NI           =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_NI);
    AN_LOG_BS           =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_BS);
    AN_LOG_ACP          =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_ACP);
    AN_LOG_MESSAGE      =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_MESSAGE);
    AN_LOG_ANRA         =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_ANRA);
    AN_LOG_EVENT        =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_EVENT);
    AN_LOG_SUDI         =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_SUDI);
    AN_LOG_TLV          =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_TLV);
    AN_LOG_MSG_MGR      =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_MSG_MGR);
    AN_LOG_IDP          =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_IDP);
    AN_LOG_IF           =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_IF);
    AN_LOG_ERR          =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_ERR);
    AN_LOG_DB           =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_DB);
    AN_LOG_IP           =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_IP);
    AN_LOG_PAK          =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_PAK);
    AN_LOG_TIMER        =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_TIMER);
    AN_LOG_AVL          =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_AVL);
    AN_LOG_SIGN         =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_SIGN);
    AN_LOG_CERT         =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_CERT);
    AN_LOG_CLI          =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_CLI);
    AN_LOG_MASA         =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_MASA);
    AN_LOG_MEM          =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_MEM);
    AN_LOG_SRVC         =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_SRVC);
    AN_LOG_TOPO         =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_TOPO);
    AN_LOG_AAA          =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_AAA);
    AN_LOG_LIST         =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_LIST);
    AN_LOG_CNP          =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_CNP);
    AN_LOG_NBR_LINK     =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_NBR_LINK);
    AN_LOG_NTP          =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_NTP);
    AN_LOG_FILE         =   AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_FILE);
    AN_LOG_ALL          =  0xFFFFFFFF;

    an_logger_initialized = TRUE;    
    return;
}

void an_logger_uninit (void)
{
    if (!an_logger_is_initialized()) {
        return;
    }
    if (log_fd_ != STDOUT_FILENO) {
        an_file_close(log_fd_);
        log_fd_ = STDOUT_FILENO;
    }
    an_logger_initialized = FALSE;
    return;
}

void an_set_log_lev (an_log_type_e log_type, an_debug_level_e lev, boolean flag)
{
    if (flag) {
        if (lev <= an_debug_map[log_type]) {
            an_debug_map[log_type] = lev;
            printf("\n\tDebugging Enabled for  %s %s",
                   an_log_cfg_string[log_type],
                   an_log_lev_str[an_debug_map[log_type]]);
        }
    } else {
        if ((lev <= an_debug_map[log_type]) && 
             (an_debug_map[log_type] != AN_DEBUG_MAX)) {
            printf("\n\tDebugging Disabled for  %s %s",
                    an_log_cfg_string[log_type],
                    an_log_lev_str[an_debug_map[log_type]]);
            an_debug_map[log_type] = AN_DEBUG_MAX;
        } 
    }
}

void an_config_debug_log (an_log_type_e type, an_debug_level_e lev, boolean flag)
{
    switch (type) {
        case AN_LOG_ND_ALL:
            an_set_log_lev(AN_LOG_ND_EVENT, lev, flag);
            an_set_log_lev(AN_LOG_ND_PACKET, lev, flag);
            an_set_log_lev(AN_LOG_ND_DB, lev, flag);
            break;
        case AN_LOG_BS_ALL:
            an_set_log_lev(AN_LOG_BS_EVENT, lev, flag);
            an_set_log_lev(AN_LOG_BS_PACKET, lev, flag);
            break;

        case AN_LOG_SRVC_ALL:
            an_set_log_lev(AN_LOG_SRVC_EVENT, lev, flag);
            an_set_log_lev(AN_LOG_SRVC_PACKET, lev, flag);
            an_set_log_lev(AN_LOG_SRVC_AAA, lev, flag);
            an_set_log_lev(AN_LOG_SRVC_NTP, lev, flag);
            an_set_log_lev(AN_LOG_SRVC_SYSLOG, lev, flag);
            an_set_log_lev(AN_LOG_SRVC_IDP, lev, flag);
            an_set_log_lev(AN_LOG_SRVC_TOPO, lev, flag);
            an_set_log_lev(AN_LOG_SRVC_CONFIG, lev, flag);
            break;
        case AN_LOG_INTENT_ALL:
            printf("\nNo intent logging is supported");
            break;
        default:
            an_set_log_lev(type, lev, flag);
            break;
    }
}

void an_debug_log_show (void)
{
    an_log_type_e log_type;
    bool printHeader = TRUE;

    for (log_type = AN_LOG_ND_EVENT; log_type < AN_LOG_ALL_ALL; log_type++) {
         if ((log_type == AN_LOG_ND_ALL) ||
             (log_type == AN_LOG_BS_ALL) ||
             (log_type == AN_LOG_SRVC_ALL) ||
             (log_type == AN_LOG_RA_ALL) ||
             (log_type == AN_LOG_INTENT_ALL) ||
             (an_debug_map[log_type] == AN_DEBUG_MAX)) {
             continue;
         } else {
            if (an_debug_map[log_type] != AN_DEBUG_MAX) {
                if (printHeader) {
                    printHeader = FALSE;
                    printf("\nDebugging is enabled for ");
                }
                printf("\n \t %s %s",an_log_cfg_string[log_type],
                       an_log_lev_str[an_debug_map[log_type]]);
            }
        }
    }
}


void an_log_start (an_log_cfg_e cfg)
{
    if (cfg == AN_LOG_CFG_ALL) {
        an_log_flag = AN_LOG_ALL;
        /* Disabling Database and Mem from all for now */
        an_log_flag &= ~(AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_DB));
        an_log_flag &= ~(AN_LOG_FLAG_FROM_LOG_CFG(AN_LOG_CFG_MEM));
    } else {
        an_log_flag |= (AN_LOG_FLAG_FROM_LOG_CFG(cfg));
        printf("\nAN %s debugging is enabled", an_log_cfg_string[cfg]);
    }

}

void an_log_stop (an_log_cfg_e cfg)
{
    if (cfg == AN_LOG_CFG_ALL) {
        an_log_flag = 0;
    } else {
        an_log_flag &= ~(AN_LOG_FLAG_FROM_LOG_CFG(cfg));
        printf("\nAN %s debugging is enabled", an_log_cfg_string[cfg]);
    }
    return;
}

boolean an_log_is_enabled_for_type (an_log_type type)
{
    return (an_log_flag & type);
}

boolean an_log_is_enabled_for_type_lev (an_log_type_e type, an_debug_level_e lev)
{
    return (an_debug_map[type] == lev);
}

boolean an_debug_log_is_enabled_for_type (an_log_type_e type)
{
     return (an_log_flag & type);
}   

boolean an_log_is_enabled_for_cfg (an_log_cfg_e cfg)
{
    return (an_log_is_enabled_for_type(AN_LOG_FLAG_FROM_LOG_CFG(cfg)));
}

boolean an_log_is_enabled (void)
{
    return (an_log_flag);
}

void an_log (an_log_type type, const uint8_t *fmt, ...)
{
    va_list args;

    if (an_log_is_enabled_for_type(type)) {
        va_start(args, fmt);
        vbuginf(fmt, args);
        va_end(args);
    }

    return;
}

void an_debug_log (an_log_type_e type, an_debug_level_e lev, 
                   void *condition, const char *fmt, ...) 
{
    va_list args;

    if (lev >= an_debug_map[type]) {
        va_start(args, fmt);
        vbuginf(fmt, args);
        va_end(args);
    }
}
 
void an_debug_log_start (boolean flag)
{
    an_log_type_e log_type;
    for (log_type = AN_LOG_ND_EVENT; log_type < AN_LOG_ALL_ALL; log_type++) {
         if (flag) {
             an_debug_map[log_type] = AN_DEBUG_SEVERE;
         } else {
             an_debug_map[log_type] = AN_DEBUG_MAX;
         }
    }
}

void an_debug_log_all (boolean sense)
{
    if (sense) {
        an_debug_log_start(TRUE);
    } else {
        an_debug_log_start(FALSE);
    }
}
            
void an_log_init (void) 
{
    an_logger_init();
    return;
}

void an_log_uninit (void) 
{
    an_logger_uninit();
}

void an_buginf (const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vbuginf(fmt, args);
    va_end(args);

    return;
}

boolean an_log_fd_set (an_file_descr_t fd)
{
    if (log_fd_ != STDOUT_FILENO) {
        an_file_close(log_fd_);
    }
    log_fd_ = fd;
    return TRUE;
}

boolean an_log_stdout_set (void)
{
    if (log_fd_ != STDOUT_FILENO) {
        an_file_close(log_fd_);
        log_fd_ = STDOUT_FILENO;
    }

    return TRUE;
}

boolean an_log_file_set (uint8_t *file_name)
{
    if (log_fd_ != STDOUT_FILENO) {
        an_file_close(log_fd_);
    }
    log_fd_ = an_file_open(file_name, O_RDWR|O_CREAT|O_APPEND);

    return (an_file_descr_is_valid(log_fd_));
}
