/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_logger.h"
#include "an_misc.h"
//#include "an_parse_dummy.h"
#include "an_tlv.h"
#include "an_file.h"
#include "an_file_linux.h"
#include "an_syslog.h"
#include <stdarg.h>
#include <string.h>

#define AN_LOG_FLAG_FROM_LOG_CFG(cfg) (an_pow(2, cfg - 1))
boolean an_debug_map[AN_LOG_ALL_ALL][AN_DEBUG_MAX];
#define AN_LINUX_LOGGER_FILENAME "an_logger.log"
#define AN_LOGGER_MAX_LINE_LEN 500

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


const uint8_t *an_log_lev_str [] = {
    "Info",
    "Moderate",
    "Severe",
    "Max",
};

const uint8_t *an_log_cfg_string [] = {
    "None",
    "AN ND Events",
    "AN ND Packets",
    "AN ND DB",
    "AN ND All",
    "AN BS Events",
    "AN BS Packets",
    "AN BS All",
    "AN RA Events",
    "AN RA DB",
    "AN RA All",
    "AN Srvc Events",
    "AN Srvc Packets",
    "AN Srvc AAA",
    "AN Srvc NTP",
    "AN Srvc SYSLOG",
    "AN Srvc IDP",
    "AN Srvc All",
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

void vbuginf(const char *fmt, va_list args) {
    an_buffer_t line = {};
    uint8_t temp_str[AN_LOGGER_MAX_LINE_LEN-1] = {};
    an_file_descr_t fd = AN_FILE_DESCR_INVALID;
    an_file_api_ret_enum retval;

   fd = an_file_open(AN_LINUX_LOGGER_FILENAME, AN_FOF_WRITE_ONLY | AN_FOF_APPEND);
   if (!an_file_descr_is_valid(fd)) { 
       fd = an_file_open(AN_LINUX_LOGGER_FILENAME, AN_FOF_WRITE_ONLY | AN_FOF_APPEND);
       if (!an_file_descr_is_valid(fd)) { 
           printf("\n Failed to open the file in vbuginf %s", AN_LINUX_LOGGER_FILENAME);
       }
       return;
    }

    retval = an_file_seek(fd, 0, AN_FILE_SEEK_END);
    if (retval != AN_FILE_API_SUCCESS) {
       printf("\nEncountered error in writing to linux logger file"
              "file %s, error code %s", AN_LINUX_LOGGER_FILENAME, an_file_enum_get_string(retval));
        an_file_close(fd);
        return;
    }
// Write to logger file here.
//    snprintf(temp_str, AN_LOGGER_MAX_LINE_LEN, fmt, args);
    vsnprintf(temp_str, AN_LOGGER_MAX_LINE_LEN, fmt, args);
    line.data = temp_str;
    line.len = strlen(temp_str)+1;
    retval = an_file_write_word(fd, &line);
    if (retval != AN_FILE_API_SUCCESS) {
        an_file_close(fd);
        return;
    }

    retval = an_file_write_line_terminator(fd);
    if (retval != AN_FILE_API_SUCCESS) {
        an_file_close(fd);
        return;
    }
    an_file_close(fd);

//    vprintf(fmt,args);
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

    an_buffer_t word = {};
    an_file_descr_t fd = AN_FILE_DESCR_INVALID;
    an_file_api_ret_enum retval;        

    fd = an_file_open(AN_LINUX_LOGGER_FILENAME, AN_FOF_READ_WRITE | AN_FOF_CREATE);
    if (!an_file_descr_is_valid(fd)) {  
       fd = an_file_open(AN_LINUX_LOGGER_FILENAME, AN_FOF_READ_WRITE | AN_FOF_CREATE);
       if (!an_file_descr_is_valid(fd)) { 
           fd = an_file_open(AN_LINUX_LOGGER_FILENAME, AN_FOF_READ_WRITE | AN_FOF_CREATE);
           if (!an_file_descr_is_valid(fd)) {    
               printf("\n Failed to open the file in an_logger_init() %s", AN_LINUX_LOGGER_FILENAME);
           }
       }
       return;
    }
 
/*
    retval = an_file_seek(fd, 0, AN_FILE_SEEK_END);
    if (retval != AN_FILE_API_SUCCESS) {
       printf("\nEncountered error in writing to linux logger file"
              "file %s, error code %s", file, an_file_enum_get_string(retval));
        an_file_close(fd);
        return;
    }
*/
    an_logger_initialized = TRUE;    
    an_file_close(fd);
    return;
}

void an_logger_uninit (void)
{
    if (!an_logger_is_initialized()) {
        return;
    }
    an_file_delete(AN_LINUX_LOGGER_FILENAME);
    an_logger_initialized = FALSE;
    return;
}

void an_set_log_lev (an_log_type_e start_log, an_log_type_e end_log, 
                     an_debug_level_e lev, boolean flag)
{
    int i;
    for (i = start_log; i <end_log; i++) {
         an_debug_map[i][lev] = flag;
         if (flag) {
            printf("\n\tDebugging is Enabled for %s %s",
                    an_log_cfg_string[i], an_log_lev_str[lev]);
         } else {
            printf("\n\tDebugging is Disabled for %s %s",
                    an_log_cfg_string[i], an_log_lev_str[lev]);
         }
    }

} 

void an_config_debug_log (an_log_type_e type, an_debug_level_e lev, boolean flag)
{
    int i;
    for (i = lev; i < AN_DEBUG_MAX; i++) {

        switch (type) {
            case AN_LOG_ND_ALL:
                 an_set_log_lev(AN_LOG_ND_EVENT, type, i, flag);
                break;
            case AN_LOG_BS_ALL:
                 an_set_log_lev(AN_LOG_BS_EVENT, type, i, flag);
                break;
            case AN_LOG_RA_ALL:
                 an_set_log_lev(AN_LOG_RA_EVENT, type, i, flag);
                 break;
            case AN_LOG_SRVC_ALL:
                 an_set_log_lev(AN_LOG_SRVC_EVENT, type, i, flag);
                 break;
            default:
                an_debug_map[type][lev] = flag;
                if (flag) {
                    printf("\n\tDebugging is Enabled for %s %s",
                           an_log_cfg_string[type], an_log_lev_str[i]);
                } else {
                    printf("\n\tDebugging is Disabled for %s %s",
                           an_log_cfg_string[type], an_log_lev_str[i]);
                }
                break;
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
    return (an_debug_map[type][lev]);
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
 //   if (an_debug_map[type][lev]) {
        va_start(args, fmt);
        vbuginf(fmt, args);
        va_end(args);
 //   }
}
 
void an_debug_log_start (boolean flag)
{
    an_debug_level_e lev;
    an_log_type_e log;

    for(lev=AN_DEBUG_INFO; lev<AN_DEBUG_MAX; lev++) {
        for (log=AN_LOG_ND_EVENT; log<AN_LOG_ALL_ALL; log++) {
            an_debug_map[log][lev] = flag;
        }
    }
}

static void an_debug_log_all (boolean sense)
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

