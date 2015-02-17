/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "../al/an_types.h"
#include "../al/an_addr.h"
#include "../al/an_logger.h"
#include "../al/an_cert.h"
#include "../al/an_if.h"
#include "../al/an_misc.h"
#include "../al/an_file.h"
#include "../al/an_mem.h"
#include "../al/an_sudi.h"
#include "../al/an_str.h"
#include "../al/an_ntp.h"
#include "../al/an_timer.h"
#include "an.h"
#include "an_anra_db.h"
#include "an_msg_mgr.h"
#include "an_event_mgr.h"
#include "an_bs.h"
#include "an_anra.h"
//#include "an_topo_disc.h"
//#include "../ios/an_parse_ios.h"

extern const uint8_t *an_cert_enum_get_string(an_cert_api_ret_enum enum_type);
extern uint16_t an_routing_ospf;
void an_anra_trigger_bs_invite_message(an_udi_t invitee_udi, 
            an_addr_t proxy_addr, an_iptable_t iptable, an_sign_t* masa_sign);
void an_anra_trigger_bs_response_message(an_cert_t *cert, an_udi_t dest_udi,
                                  an_addr_t proxy_device, an_iptable_t iptable);
void an_anra_trigger_bs_reject_message(an_udi_t invitee_udi, 
            an_addr_t proxy_addr, an_iptable_t iptable);
void an_anra_trigger_bs_enroll_quarantine_message(an_udi_t invitee_udi,
            an_addr_t proxy_addr, an_iptable_t iptable);
void an_anra_init(void);
extern void an_anra_cfg_ca_server(anr_ca_server_command_e command);
extern boolean an_anra_cs_up(void);
extern an_avl_tree an_accepted_device_tree;
extern an_avl_tree an_anra_color_device_tree;
extern an_avl_tree an_anra_quarantine_device_tree;
an_avl_compare_e an_quarantine_device_compare(an_avl_node_t *node1, an_avl_node_t *node2);
an_avl_compare_e an_accepted_device_compare(an_avl_node_t *node1, an_avl_node_t *node2);
an_avl_compare_e an_anra_color_device_compare(an_avl_node_t *node1, an_avl_node_t *node2);
extern an_addr_t anr_reg_address[3];

#define ANRA_DEVICE_SUFFIX_POOL_SIZE 128
#define ANR_MAX_FILE_ENTRIES 8000
#define ANRA_MAX_WORD_LEN 128
#define ANRA_MAX_LINE_LEN 128
#define ANRA_MAX_UDI_LEN 128

#define AN_REGISTRAR_ACCEPTED_DEVICE_FILENAME "ANR_ACC.an"
#define AN_REGISTRAR_QUARANTINE_DEVICE_FILENAME "ANR_QUA.an"
#define AN_REGISTRAR_DEVICE_ID_PREFIX "Router-"
uint8_t an_chassis_mac[AN_IEEEBYTES];
//uint8_t anr_id_devicename[ANR_MAXHOSTNAMELEN + 1];
uint8_t *an_anr_service_name;

typedef enum anr_info_state_e_ {
    ANR_INFO_STATE_NONE             =   0,
    ANR_INFO_STATE_INIT             =   1,
    ANR_INFO_STATE_SHUT             =   2,
    ANR_INFO_STATE_SHUT_PENDING     =   3,
    ANR_INFO_STATE_LIVE             =   4,
    ANR_INFO_STATE_LIVE_PENDING     =   5,
    ANR_INFO_STATE_LIVE_PEN_CA      =   6,
} anr_info_state_e;

static const uint8_t *anr_info_state_str[] = {

     "Autonomic Registrar Not Configured",
     "Autonomic Registrar in Configuration",
     "Autonomic Registrar Shut",
     "Autonomic Registrar Shut Pending",
     "Autonomic Registrar Live",
     "Autonomic Registrar Unshut Pending",
     "Autonomic Registrar CA Live Pending",
};

static uint8_t *anr_ca_name_str[] = {
    "NO CA",
    "IOS CA",
    "IOS RA",
};

typedef struct anra_info_t_ {
    anr_info_state_e state;
    uint8_t *domain_id;
    uint8_t *device_id;
    uint8_t *device_id_prefix;
    uint8_t *whitelist_filename;
    anr_ca_type_e ca_type;
    uint8_t *db_url;
    uint8_t *ca_url;
    uint8_t *vrf_name;
    boolean checkUDI;
    an_addr_t registrar_ip;
    an_mac_addr *macaddress;
} anra_info_t;

anra_info_t anra_info = {};

an_timer an_anra_cs_check_timer;
#define AN_ANRA_CS_CHECK_INTERVAL 15*1000

static uint8_t anra_device_suffix_pool[ANRA_DEVICE_SUFFIX_POOL_SIZE];
static uint32_t anra_device_suffix_pool_current_index = 0;
static uint16_t an_anra_get_device_suffix_from_device_id(uint8_t *device_id);
static uint32_t an_anra_allocate_device_suffix(uint16_t index);

/*************************** ANRA FIle Operations *****************************/

boolean
an_anra_write_accepted_device_to_file (an_accepted_device_t *accepted_device)
{
    an_file_descr_t fd = AN_FILE_DESCR_INVALID;
    an_buffer_t word = {};
    uint8_t file[AN_STR_MAX_LEN] = {};
    an_file_api_ret_enum retval;

    if (!accepted_device) {
        return (FALSE);
    }

    an_snprintf(file, AN_STR_MAX_LEN, "%s%s", an_anra_get_db_url(), 
                        AN_REGISTRAR_ACCEPTED_DEVICE_FILENAME);

    fd = an_file_open(file, AN_FOF_WRITE_ONLY | AN_FOF_APPEND);
    if (!an_file_descr_is_valid(fd)) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to open the file %s, trying the create", 
                     an_ra_db, file);

        fd = an_file_open(file, AN_FOF_WRITE_ONLY | AN_FOF_APPEND | 
                                AN_FOF_CREATE);
        if (!an_file_descr_is_valid(fd)) {
            DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                         "\n%sFailed to create the file %s", 
                         an_ra_db, file);
            return (FALSE);
        }
    }

    retval = an_file_seek(fd, 0, AN_FILE_SEEK_END); 
    if (retval != AN_FILE_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sEncountered error in writing accepted device to "
                     "file %s, error code %s", 
                     an_ra_db, file, an_file_enum_get_string(retval));
        an_file_close(fd);
        return (FALSE);
    }

    word.len = an_udi_trim_and_get_len(accepted_device->udi.data);
    word.data = accepted_device->udi.data; 
    retval = an_file_write_word(fd, &word);
    if (retval != AN_FILE_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                 "\n%sFailed to write accepted Device UDI [%s] to the file %s", 
                  an_ra_db, word.data, file);
        an_file_close(fd);
        return (FALSE);
    }

    word.len = an_udi_trim_and_get_len(accepted_device->device_id);
    word.data = accepted_device->device_id;
    retval = an_file_write_word(fd, &word);
    if (retval != AN_FILE_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                 "\n%sFailed to write accepted Device ID [%s] to the file %s",
                 an_ra_db, word.data, file);
        an_file_close(fd);
        return (FALSE);
    }

    retval = an_file_write_line_terminator(fd);
    if (retval != AN_FILE_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sEncountered error in writing accepted device [%s] "
                     "to file %s, error code %s", an_ra_db,
                     word.data, file, an_file_enum_get_string(retval));
        an_file_close (fd);
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                 "\n%sAccepted Device [%s] written to the file %s",
                 an_ra_db, accepted_device->udi.data, file);

    an_file_copy_to_stby_later(file);
    an_file_close(fd);
    return (TRUE);
}

static boolean
an_anra_write_quarantine_device_to_opened_file (an_file_descr_t fd, 
                        an_anra_quarantine_device_t *quarantine_device)
{
    an_buffer_t line = {};
    an_file_api_ret_enum retval;

    if (!an_file_descr_is_valid(fd) || 
        !quarantine_device->udi.len || !quarantine_device->udi.data) {
        return (FALSE);
    }

    line.len = an_udi_trim_and_get_len(quarantine_device->udi.data);
    line.data = quarantine_device->udi.data;
    retval = an_file_write_line(fd, &line);
    if (retval != AN_FILE_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sEncountered error in writing quarantine device %s "
                     "to opened file, error code %s", 
                     an_ra_db, line.data, an_file_enum_get_string(retval));
        return (FALSE);
    }

    return (TRUE);
}

boolean
an_anra_write_quarantine_device_to_file (an_anra_quarantine_device_t 
                                         *quarantine_device)
{
    an_file_descr_t fd = AN_FILE_DESCR_INVALID;
    uint8_t file[AN_STR_MAX_LEN] = {};
    an_file_api_ret_enum retval;

    if (!quarantine_device) {
        return (FALSE);
    }
    an_snprintf(file, AN_STR_MAX_LEN, "%s%s", an_anra_get_db_url(), 
                        AN_REGISTRAR_QUARANTINE_DEVICE_FILENAME);

    fd = an_file_open(file, AN_FOF_WRITE_ONLY | AN_FOF_APPEND);
    if (!an_file_descr_is_valid(fd)) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to open the file %s, trying the create", 
                     an_ra_db, file);

        fd = an_file_open(file, AN_FOF_WRITE_ONLY | AN_FOF_APPEND | AN_FOF_CREATE);
        if (!an_file_descr_is_valid(fd)) {
            DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                         "\n%sFailed to create the file %s", 
                         an_ra_db, file);
            return (FALSE);
        }
    }

    retval = an_file_seek(fd, 0, AN_FILE_SEEK_END);
    if (retval != AN_FILE_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sWhile writing quarantine device to file %s, %s", 
                     an_ra_db, file, an_file_enum_get_string(retval));
        an_file_close(fd);
        return (FALSE);
    }

    if (!an_anra_write_quarantine_device_to_opened_file(fd, quarantine_device)) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to write quarantine device [%s] to file %s", 
                     an_ra_db, quarantine_device->udi.data, file);
        return (FALSE);
    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sQuarantine Device [%s]  written to the file %s",
                 an_ra_db, quarantine_device->udi.data, file);

    an_file_copy_to_stby_later(file);
    an_file_close(fd);
    return (TRUE);
}

an_avl_walk_e
an_anra_write_full_quarantine_device_db_cb (an_avl_node_t *node, void *args)
{
    an_file_descr_t *fd = NULL;

    if (!node || !args) {
        return (AN_AVL_WALK_FAIL);
    }

    fd = (an_file_descr_t *)args;
    if (an_anra_write_quarantine_device_to_opened_file(*fd, 
                          (an_anra_quarantine_device_t *)node)) {
        return (AN_AVL_WALK_SUCCESS);
    } else {
        return (AN_AVL_WALK_FAIL);
    }
}

boolean
an_anra_write_full_quarantine_device_db_to_file (void)
{
    an_file_descr_t fd = AN_FILE_DESCR_INVALID;
    uint8_t file[AN_STR_MAX_LEN] = {};

    an_snprintf(file, AN_STR_MAX_LEN, "%s%s", an_anra_get_db_url(), 
                        AN_REGISTRAR_QUARANTINE_DEVICE_FILENAME);

    /* Delete the old file */
    an_file_delete(file);

    fd = an_file_open(file, AN_FOF_WRITE_ONLY | AN_FOF_CREATE);
    if (!an_file_descr_is_valid(fd)) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to open the file %s", an_ra_db, file);
        return (FALSE);
    }

    an_anra_quarantine_device_db_walk(
            an_anra_write_full_quarantine_device_db_cb, &fd);

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                 "\n%sQuarantine Device written to the file %s",
                 an_ra_db, file);
    an_file_copy_to_stby_later(file);
    an_file_close(fd);
    return (TRUE);
}

boolean 
an_anra_read_whitelist_device_db_from_file (uint8_t *whitelist_filename)
{
    uint16_t i = 0, entries_read = 0;
    an_anra_color_device_t *whitelist_device = NULL;
    an_buffer_t line = {};
    an_file_descr_t fd = AN_FILE_DESCR_INVALID;
    an_file_api_ret_enum retval;

    if (!whitelist_filename) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sWhitelist filename doesn't exist", an_ra_db);
        return FALSE;
    }    

    fd = an_file_open(whitelist_filename, AN_FOF_READ_ONLY);
    if (!an_file_descr_is_valid(fd)) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to open whitelist file %s", 
                     an_ra_db, whitelist_filename);

        printf("\n%%Autonomic Registrar failed to open whitelist file %s, Autonomic Registrar not unshut", 
               whitelist_filename);
        return FALSE;
    }

    retval = an_file_seek(fd, 0, AN_FILE_SEEK_SET);
    if (retval != AN_FILE_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                "\n%sWhile reading whitelist device from file %s, got error %s", 
                 an_ra_db, whitelist_filename, an_file_enum_get_string(retval));
        an_file_close(fd);
        return (FALSE);
    }

    i = 0, entries_read = 0;
    while (an_file_read_next_line(fd, &line, ANRA_MAX_LINE_LEN) 
           == AN_FILE_API_SUCCESS) {

        i = (i+1)%20;
        if (!i) {
            an_thread_check_and_suspend();
        }
        entries_read++;

        if (entries_read > ANR_MAX_FILE_ENTRIES) {
            DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                    "\n%sMaximum supported file entries = [%d]. Ignoring other"
                    " entries from whitelist file %s", 
                    an_ra_db, ANR_MAX_FILE_ENTRIES, whitelist_filename);
            printf("\n%%Maximum supported file entries = %d. " 
                   "Ignoring other entries from whitelist file %s", 
                   ANR_MAX_FILE_ENTRIES, whitelist_filename);
            break;
        }

        if (line.len) {
            if (!an_udi_is_format_valid((an_udi_t *)&line)) {
                DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                             "\n%sFound an invalid UDI %s, aborting read from "
                             "%s", an_ra_db, line.data, whitelist_filename);
                break;
            }
            whitelist_device = an_anra_color_device_alloc();
            an_str_alloc_and_copy_buffer(&line, &whitelist_device->udi.data, 
                        &whitelist_device->udi.len, 
                        "Autonomic Registrar Whitelist Dev UDI");
            whitelist_device->label = AN_WHITELIST_DEVICE; 
            if (!an_anra_color_device_db_insert(whitelist_device)) {
                an_anra_color_device_free(whitelist_device);
            }
        }
    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sRead Whitelist DB from file %s", an_ra_db, 
                 whitelist_filename);
    an_file_close(fd);
    return TRUE;
}

boolean 
an_anra_read_accepted_device_db_from_file (void)
{
    uint16_t i = 0, entries_read = 0;
    an_accepted_device_t *accepted_device = NULL;
    an_buffer_t device_id = {};
    an_udi_t udi = {};
    an_file_descr_t fd = AN_FILE_DESCR_INVALID;
    uint8_t file[AN_STR_MAX_LEN] = {};
    uint16_t device_suffix = 0;
    an_file_api_ret_enum retval;

    an_snprintf(file, AN_STR_MAX_LEN, "%s%s", an_anra_get_db_url(), 
                        AN_REGISTRAR_ACCEPTED_DEVICE_FILENAME);

    fd = an_file_open(file, AN_FOF_READ_ONLY);
    if (!an_file_descr_is_valid(fd)) {
        return FALSE;
    }

    retval = an_file_seek(fd, 0, AN_FILE_SEEK_SET);
    if (retval != AN_FILE_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                "\n%sWhile reading accepted device from file %s, got error %s", 
                 an_ra_db, file, an_file_enum_get_string(retval));
        an_file_close(fd);
        return (FALSE);
    }

    i = 0, entries_read = 0;
    while (TRUE) {

        i = (i+1)%20;
        if (!i) {
            an_thread_check_and_suspend();
        }
        entries_read++;
        if (entries_read > ANR_MAX_FILE_ENTRIES) {
            DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                    "\n%sMaximum supported file entries = [%d]. Ignoring other"
                    " entries from accepted file %s", 
                    an_ra_db, ANR_MAX_FILE_ENTRIES, file);
            printf("\n%%Maximum supported file entries = %d. " 
                   "Ignoring other entries from accepted file %s", 
                   ANR_MAX_FILE_ENTRIES, file);
            break;
        }

        /* Read UDI */
        retval = an_file_read_next_udi(fd, &udi, ANRA_MAX_UDI_LEN);
        if (retval != AN_FILE_API_SUCCESS) { 
            DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                         "\n%sFailed to read udi from %s", an_ra_db, file);
            break;
        }

        if (!an_udi_is_format_valid(&udi)) {
            DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                         "\n%sFound an invalid UDI %s, aborting read from %s",
                         an_ra_db, udi.data, file);

            break;
        }

        /* Read device-name */
        retval = an_file_read_next_word(fd, &device_id, ANRA_MAX_WORD_LEN);
        if (retval != AN_FILE_API_SUCCESS) {
            DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                "\n%sWhile reading accepted device from file %s, got error %s", 
                 an_ra_db, file, an_file_enum_get_string(retval));
            break;
        }

        device_suffix = 
                an_anra_get_device_suffix_from_device_id(device_id.data);
        if (!an_anra_allocate_device_suffix(device_suffix)) { 
            break;
        }
        
        accepted_device = an_accepted_device_alloc();

        an_str_alloc_and_copy_buffer((an_buffer_t *)&udi, 
                &accepted_device->udi.data, &accepted_device->udi.len, 
                "Autonomic Registrar Read Acc Dev UDI");
        an_str_alloc_and_copy_buffer(&device_id, &accepted_device->device_id, 
                NULL, "Autonomic Registrar Read Acc Dev Dev");

        accepted_device->device_suffix = device_suffix;

        accepted_device->addr = an_get_v6addr_from_names(anra_info.domain_id, 
                           anra_info.macaddress, accepted_device->device_id);
        accepted_device->router_id = an_get_v4addr_from_names(
                                                 anra_info.domain_id, 
                                                 accepted_device->device_id);
        if (!an_accepted_device_db_insert(accepted_device)) {
            an_accepted_device_free(accepted_device);
        }

    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                 "\n%sRead accepted device[%s] from Accepted DB", 
                 udi.data, an_ra_db);
    an_file_close(fd);
    return TRUE;
}

boolean 
an_anra_read_quarantine_device_db_from_file (void)
{
    uint16_t i = 0, entries_read = 0;
    an_anra_quarantine_device_t *quarantine_device = NULL;
    an_buffer_t line = {};
    an_file_descr_t fd = AN_FILE_DESCR_INVALID;
    uint8_t file[AN_STR_MAX_LEN] = {};
    an_file_api_ret_enum retval;

    an_snprintf(file, AN_STR_MAX_LEN, "%s%s", an_anra_get_db_url(), 
                        AN_REGISTRAR_QUARANTINE_DEVICE_FILENAME);

    fd = an_file_open(file, AN_FOF_READ_ONLY);
    if (!an_file_descr_is_valid(fd)) {
        return FALSE;
    }

    retval = an_file_seek(fd, 0, AN_FILE_SEEK_SET);
    if (retval != AN_FILE_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
              "\n%sWhile reading quarantine device from file %s, got error %s", 
              an_ra_db, file, an_file_enum_get_string(retval));
        an_file_close(fd);
        return (FALSE);
    }

    i = 0;
    entries_read = 0;
    while (an_file_read_next_line(fd, &line, 100) == AN_FILE_API_SUCCESS) {

        i = (i+1)%20;
        if (!i) {
            an_thread_check_and_suspend();
        }
        entries_read++;
        if (entries_read > ANR_MAX_FILE_ENTRIES) {
            DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                    "\n%sMaximum supported file entries = [%d]. Ignoring other"
                    " entries from quarantine file %s", 
                    an_ra_db, ANR_MAX_FILE_ENTRIES, file);
            printf("\n%%Maximum supported file entries = %d. " 
                   "Ignoring other entries from quarantine file %s", 
                   ANR_MAX_FILE_ENTRIES, file);
            //continue;
            break;
        }
        if (!an_udi_is_format_valid((an_udi_t *)&line)) {
            DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                         "\n%sFound an invalid UDI %s, aborting read from %s", 
                         an_ra_db, line.data, file);
            break;
        }
        quarantine_device = an_anra_quarantine_device_alloc();
        an_str_alloc_and_copy_buffer(&line, &quarantine_device->udi.data, 
                           &quarantine_device->udi.len,
                           "Autonomic Registrar Quar Dev UDI");

        if (!an_anra_quarantine_device_db_insert(quarantine_device)) {
            an_anra_quarantine_device_free(quarantine_device);
        }
    } 

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, "\n%sRead quarantine db "
                 "from file %s", an_ra_db, file);
    an_file_close(fd);
    return (TRUE);
}

void
an_anr_copy_files ()
{
    uint8_t file[AN_STR_MAX_LEN] = {};

    an_snprintf(file, AN_STR_MAX_LEN, "%s%s", an_anra_get_db_url(), 
                        AN_REGISTRAR_ACCEPTED_DEVICE_FILENAME);
    an_file_copy_to_standby(file);

    an_snprintf(file, AN_STR_MAX_LEN, "%s%s", an_anra_get_db_url(), 
                        AN_REGISTRAR_QUARANTINE_DEVICE_FILENAME);
    an_file_copy_to_standby(file);

    an_snprintf(file, AN_STR_MAX_LEN, "%s%s.%s", an_anra_get_db_url(), 
                                            ANRA_CS_TP_LABEL, "ser");
    an_file_copy_to_standby(file);

    an_snprintf(file, AN_STR_MAX_LEN, "%s%s.%s", an_anra_get_db_url(), 
                                            ANRA_CS_TP_LABEL, "crl");
    an_file_copy_to_standby(file);

    an_snprintf(file, AN_STR_MAX_LEN, "%s%s_%s", an_anra_get_db_url(), 
                                            ANRA_CS_TP_LABEL, "00001.pem");
    an_file_copy_to_standby(file);

    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                "\nCopying ANR files to Hot standby");
    
    return;
}

void
an_anra_notify_cert_enrollment_done (an_cert_t *device_cert, an_udi_t dest_udi,
                                     an_addr_t proxy_device, an_iptable_t iptable)
{
    uint8_t anr_file[AN_STR_MAX_LEN] = {};

    if (!device_cert) {
       return;
    }
    an_snprintf(anr_file, AN_STR_MAX_LEN, "%s%s.%s",
                     an_anra_get_db_url(), ANRA_CS_TP_LABEL, "ser");
    an_file_copy_to_stby_later(anr_file);                                

    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                "\nCopying ANR files to standby");
    an_anra_trigger_bs_response_message(device_cert, dest_udi, proxy_device, iptable);
}

/************************* End of ANRA FIle Operations ****************************/

static void
an_anra_init_device_suffix_pool (uint32_t current_index)
{
    uint32_t i = 0;

    anra_device_suffix_pool_current_index = current_index;

    for (i=1; i<=current_index; i++) {
        anra_device_suffix_pool[i] = 1;
    }

    for (i=current_index+1; i<ANRA_DEVICE_SUFFIX_POOL_SIZE; i++) {
        anra_device_suffix_pool[i] = 0;
    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                 "\n%sInitialized Autonomic Registrar device ID pool", an_ra_db);
}

static uint32_t 
an_anra_allocate_device_suffix (uint16_t index)
{
    uint32_t i = 0;
    uint32_t device_suffix = 0;

    if (index) {
        if (!anra_device_suffix_pool[index]) {
            device_suffix = index;
            anra_device_suffix_pool[device_suffix] = 1;
            if (device_suffix > anra_device_suffix_pool_current_index) {
                anra_device_suffix_pool_current_index = device_suffix;
            }
        }
    } else {
    for (i=0; i<ANRA_DEVICE_SUFFIX_POOL_SIZE; i++) {
        anra_device_suffix_pool_current_index++;
        if (anra_device_suffix_pool_current_index == 
                    ANRA_DEVICE_SUFFIX_POOL_SIZE) {
            anra_device_suffix_pool_current_index = 0;
        }
        if (!anra_device_suffix_pool[anra_device_suffix_pool_current_index]) {
            device_suffix = anra_device_suffix_pool_current_index;
            anra_device_suffix_pool[device_suffix] = 1;
            break;
        }
    }
    }

//    an_anra_write_device_suffix_pool_current_index_to_file();

    return (device_suffix);
}

static uint16_t
an_anra_get_device_suffix_from_device_id (uint8_t *device_id)
{
    uint16_t suffix = 0;
    uint16_t i = 0;

    if (!device_id || !anra_info.device_id_prefix) {
        return (0);
    }

    /* device-id should starts with device_id_prefix */
    if (an_strncmp(device_id, anra_info.device_id_prefix, 
                an_strlen(anra_info.device_id_prefix))) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice %s does not start with prefix %s",
                     an_ra_db, device_id, anra_info.device_id_prefix);
        return (0);
    }
    
    for (i = an_strlen(anra_info.device_id_prefix); i < an_strlen(device_id); 
             i++) {
        if ((device_id[i] < '0') || (device_id[i] > '9')) {
           /* Non Number character */ 
            DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                         "\n%sDevice-Id Suffix %c has non number char", 
                         an_ra_db, device_id[i]);
            return (0);
        } else {
            suffix = (suffix*10) + (device_id[i] - '0');
        } 
    }

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, "\n%sGot Device "
                 "suffix is %d", an_ra_db, suffix);


    return (suffix);
}

static uint8_t *
an_anra_add_assign_member_device_id (an_udi_t udi)
{
    uint32_t device_suffix = 0;
    uint8_t suffix_len = 0, device_id_len = 0;
    uint8_t *device_id = NULL;
    an_accepted_device_t *member = NULL;
    if (!udi.data) {
        return (NULL);
    }    

    member = an_accepted_device_db_search(udi);

    if (member)  {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sFound accepted device [%s] of device_id [%s]", 
                     an_ra_db, udi.data, 
                     member->device_id);
        return (member->device_id);
    } 
    
    member = an_accepted_device_alloc();
    member->udi.data = (uint8_t *)an_malloc_guard(udi.len, 
                                    "AN RA Accepted Device UDI");
    if (!member->udi.data) {
        an_accepted_device_free(member);
        return (NULL);
    }

    member->udi.len = udi.len;
    an_memcpy_guard_s(member->udi.data, member->udi.len, udi.data, udi.len);

    device_suffix = an_anra_allocate_device_suffix(0);
    suffix_len = 5;
    device_id_len = suffix_len + an_strlen(anra_info.device_id_prefix) + 1;
    device_id = (uint8_t *)an_malloc_guard(device_id_len, 
                                    "AN RA Accepted Device ID");
    if (!device_id) {
        an_accepted_device_free(member);
        return (NULL);
    }
    an_snprintf(device_id, device_id_len, "%s%c%d", 
                anra_info.device_id_prefix, AN_HOSTNAME_SUFFIX_DELIMITER, 
                device_suffix);
    member->device_suffix = device_suffix;
    member->device_id = device_id;

    member->addr = an_get_v6addr_from_names(anra_info.domain_id,
                               anra_info.macaddress, device_id);
    member->router_id = an_get_v4addr_from_names(anra_info.domain_id, 
                                                 device_id);
    if (!an_accepted_device_db_insert(member)) {
        an_accepted_device_free(member);
        return (NULL);
    }

    an_syslog(AN_SYSLOG_DEVICE_ALLOWED,
              member->udi.data, anra_info.domain_id, 
              an_addr_get_string(&member->addr),
              member->device_id);

//    an_anra_write_device_suffix_pool_current_index_to_file();
    an_write_device_from_db_to_local_file(member, AN_ACCEPTED_FILE_IDENTIFIER);
    return (member->device_id);
}

void
an_anra_set_local_anra_ip (void)
{
    an_addr_t registrar_ip = AN_ADDR_ZERO;

    registrar_ip  = an_get_v6addr_from_names(anra_info.domain_id, 
                      anra_info.macaddress, anra_info.device_id);

    anra_info.registrar_ip = registrar_ip;
}

anr_config_err_e
an_anra_set_device_id (uint8_t *device_id)
{
    if (anra_info.device_id) {
        an_free_guard(anra_info.device_id);
        anra_info.device_id = NULL;
    }

    if (device_id) {
        anra_info.device_id = (uint8_t *)an_malloc_guard(
                                         an_strlen(device_id)+1, 
                                         "Autonomic Registrar device id");
        if (anra_info.device_id) {
            an_memcpy_guard_s(anra_info.device_id, an_strlen(device_id)+1, 
                              device_id, an_strlen(device_id)+1);
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sAutonomic Registrar's device_id is set to %s",
                         an_ra_event, anra_info.device_id);
        } else {
            return (ANR_CONFIG_ERR_NOT_CONFIG);
        }
    }

    return (ANR_CONFIG_ERR_NONE);
}

anr_config_err_e
an_anra_set_mac_address (an_mac_addr *mac_address)
{   
    if (anra_info.macaddress) {
        an_free_guard(anra_info.macaddress);
        anra_info.macaddress = NULL;
    }   

    if (mac_address) {
        anra_info.macaddress = (an_mac_addr *)an_malloc_guard(
                                an_strlen(mac_address)+1,
                               "Autonomic Registrar MAC Address");
        if (anra_info.macaddress) {
           an_memcpy_guard(anra_info.macaddress, mac_address,
                            an_strlen(mac_address)+1);
           DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sAutonomic Registrar's MAC Address is set to %s",
                         an_ra_event, anra_info.macaddress);
        } else {
            return (ANR_CONFIG_ERR_NOT_CONFIG);
        }
    }

    return (ANR_CONFIG_ERR_NONE);
}

an_mac_addr*
an_anra_get_mac_address (void)
{
    return (anra_info.macaddress);
}

anr_config_err_e
an_anr_set_service_name (an_mac_addr *mac_address)
{
    if (an_anr_service_name) {
        an_free_guard(an_anr_service_name);
        an_anr_service_name = NULL;
    }

    if (mac_address) {
        an_anr_service_name = (an_mac_addr *)an_malloc_guard(
                                           an_strlen(mac_address)+1,
                                           "Service Name");
        if (an_anr_service_name) {
           DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                       "\n%sAutonomic Registrar's Service name is set to %s",
                       an_ra_event, an_anr_service_name);
        } else {
            return (ANR_CONFIG_ERR_NOT_CONFIG);
        }
    }

    return (ANR_CONFIG_ERR_NONE);
}

an_mac_addr*
an_anr_get_servcie_name (void)
{
    return (an_anr_service_name);
}

boolean
an_anra_bootstrap_thyself (void)
{
    an_udi_t udi = {};

    if (!an_get_udi(&udi)) { 
        DEBUG_AN_LOG(AN_LOG_BS_PACKET,AN_DEBUG_MODERATE, NULL, 
                     "\n%sFailed to bootstrap Registrar thyself, Null UDI", 
                     an_bs_pak);
    } else {
        an_anra_set_device_id(an_anra_add_assign_member_device_id(udi));
        an_anra_set_local_anra_ip();
        an_anra_trigger_bs_invite_message(udi, anra_info.registrar_ip,
                                an_get_iptable(), NULL);
    }

    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                 "\n%sConfigured Local AN", an_bs_pak);

 
    return (TRUE);
}

void
an_anra_cs_check (void)
{
    an_cert_t domain_cert = {};
    uint8_t anr_file[AN_STR_MAX_LEN] = {};
    if (an_anra_cs_up()) {
        if (!an_tp_exists(AN_DOMAIN_TP_LABEL) ||
            !an_get_device_id() || !an_get_domain_id() ||
            !an_get_domain_cert(&domain_cert)) {

            an_snprintf(anr_file, AN_STR_MAX_LEN, "%s%s_%s",
                           an_anra_get_db_url(), ANRA_CS_TP_LABEL, "00001.pem");
            an_file_copy_to_stby_later(anr_file);
            an_snprintf(anr_file, AN_STR_MAX_LEN, "%s%s.%s",
                                 an_anra_get_db_url(), ANRA_CS_TP_LABEL, "crl");
            an_file_copy_to_stby_later(anr_file);

            an_anra_bootstrap_thyself();
            an_syslog(AN_SYSLOG_ANRA_UP, an_get_device_id(), an_get_domain_id());

            an_event_anra_up_locally();

            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%sAN Registrar is Live", an_ra_event);
            //topo_disc_initiate();

        }
    } else {
        an_timer_start(&an_anra_cs_check_timer, AN_ANRA_CS_CHECK_INTERVAL);
    }
}

/***************************** ANRA - Configuration Section ************************/

const uint8_t *
an_anra_get_state_name (void)
{
    return (anr_info_state_str[anra_info.state]);
}

uint8_t *
an_anra_get_ca_type_name (void)
{
    return (anr_ca_name_str[anra_info.ca_type]);
}

uint8_t *
an_anra_get_ca_type_id_to_str (anr_ca_type_e ca_type)
{
    return (anr_ca_name_str[ca_type]);
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

boolean
an_anra_is_device_ra_and_not_bootstraped (void)
{
    an_cert_t domain_cert = {};
    boolean cert_present = an_get_domain_cert(&domain_cert);
    //Check if there is no domain cert or Domain cert is there but invalid
    if ( (an_anra_is_configured() && !cert_present) ||
         (cert_present && !domain_cert.valid) ) {
        return (TRUE);
    }
    return (FALSE);
}

boolean
an_anra_is_device_not_ra_and_bootstrapped (void)
{
    if (an_tp_exists(ANRA_CS_TP_LABEL)) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAutonomic Registrar has CA", 
                     an_ra_event);
        return (FALSE);
    }
    
    if (!an_tp_exists(AN_DOMAIN_TP_LABEL)) {
        return (FALSE);
    }

    return (TRUE);
}

anr_config_err_e
an_anra_config_init (void)
{
    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (anra_info.state == ANR_INFO_STATE_NONE) {
        anra_info.state = ANR_INFO_STATE_INIT;
        an_anra_set_domain_id(NULL);
        anra_info.device_id_prefix = NULL;
        an_anra_set_whitelist_filename(NULL);
        an_anra_set_ca_url(NULL);
        an_anra_set_ca_vrf(NULL);
        an_anra_set_ca_type(ANR_NO_CA);
        anra_info.checkUDI = FALSE;
        an_anra_set_db_url(AN_REGISTRAR_DEFAULT_DB_URL);

        an_event_registrar_init();

        an_bs_erase_unfinished_bootstrap();
    }

    return (ANR_CONFIG_ERR_NONE);
}

boolean 
an_anra_is_configured (void)
{
    return (anra_info.state != ANR_INFO_STATE_NONE);
}

boolean
an_anra_is_shut (void)
{
    return (anra_info.state == ANR_INFO_STATE_SHUT);
}

boolean
an_anra_is_live (void)
{
    return (anra_info.state == ANR_INFO_STATE_LIVE);
}

boolean
an_anra_is_live_pen_ca (void)
{
    return (anra_info.state == ANR_INFO_STATE_LIVE_PEN_CA);
}


boolean
an_anra_is_minimum_config_done (void)
{
    if (!an_anra_is_configured()) {
        return (FALSE);
    }

    if (!anra_info.domain_id) {
        return (FALSE);
    }

    if (!an_anra_is_ca_configured()) {
        return (FALSE);
    }

    return (TRUE);
}

anr_config_err_e
an_anra_set_db_url (uint8_t *db_url)
{
    if (an_anra_is_device_not_ra_and_bootstrapped()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAutonomic Registrar is live, can't change the "
                     "current DB URL",
                     an_ra_event);
        return (ANR_CONFIG_ERR_LIVE);
    }

    if (anra_info.db_url) {
        an_free_guard(anra_info.db_url);
        anra_info.db_url = NULL;
    }

    if (db_url) {
        anra_info.db_url = (uint8_t *)an_malloc_guard(an_strlen(db_url)+1,
                                           "AN RA CFG DB URL");
        if (anra_info.db_url) {
            an_memcpy_guard_s(anra_info.db_url, an_strlen(db_url)+1, db_url,
                                                  an_strlen(db_url)+1);
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sDB URL [%s] is set for the Autonomic Registrar",
                         an_ra_event, anra_info.db_url);
        } else {
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sFailed to set the DB URL [%s], malloc failed",
                         an_ra_event, anra_info.db_url);
            return (ANR_CONFIG_ERR_NOT_CONFIG);
        }
    }
    return (ANR_CONFIG_ERR_NONE);
}

anr_config_err_e
an_anra_set_ca_url (uint8_t *ca_url)
{
    if (an_anra_is_device_not_ra_and_bootstrapped()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAutonomic Registrar is live, can't change the "
                     "current domain",
                     an_ra_event);
        return (ANR_CONFIG_ERR_LIVE);
    }

    if (anra_info.ca_url) {
        an_free_guard(anra_info.ca_url);
        anra_info.ca_url = NULL;
    }

    if (ca_url) {
        anra_info.ca_url = (uint8_t *)an_malloc_guard(an_strlen(ca_url)+1,
                                           "AN RA CFG CA URL");
        if (anra_info.ca_url) {
            an_memcpy_guard_s(anra_info.ca_url, an_strlen(ca_url)+1, ca_url,
                                                  an_strlen(ca_url)+1);
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sCA URL [%s] is set for the Autonomic Registrar",
                         an_ra_event, anra_info.ca_url);
        } else {
            return (ANR_CONFIG_ERR_NOT_CONFIG);
        }
    }

    return (ANR_CONFIG_ERR_NONE);
}

anr_config_err_e
an_anra_set_ca_vrf (uint8_t *vrf_name)
{
    if (an_anra_is_device_not_ra_and_bootstrapped()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAutonomic Registrar is live, can't change the "
                     "current domain",
                     an_ra_event);
        return (ANR_CONFIG_ERR_LIVE);
    }

    if (anra_info.vrf_name) {
        an_free_guard(anra_info.vrf_name);
        anra_info.vrf_name = NULL;
    }

    if (vrf_name) {
        anra_info.vrf_name = (uint8_t *)an_malloc_guard(an_strlen(vrf_name) + 1,
                                    "AN RA CFG VRF");
        if (anra_info.vrf_name) {
            an_memcpy_guard(anra_info.vrf_name, vrf_name,
                            an_strlen(vrf_name) + 1);
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sVRF [%s] is set for the Autonomic Registrar",
                         an_ra_event, anra_info.vrf_name);
        } else {
            return (ANR_CONFIG_ERR_NOT_CONFIG);
        }
    }

    return (ANR_CONFIG_ERR_NONE);
}

anr_config_err_e
an_anra_set_domain_id (uint8_t *domain_id)
{
    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (!an_is_active_rp()) {
        if (an_anra_is_live_pen_ca()) {
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%sAutonomic Registrar is live, can't change the "
                        "current domain",
                        an_ra_event);
            return (ANR_CONFIG_ERR_LIVE);
        }
    } else if (an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sAutonomic Registrar is live, can't change the "
                     "current domain",
                     an_ra_event);
        return (ANR_CONFIG_ERR_LIVE);
    }

    if (anra_info.domain_id) {
        an_free_guard(anra_info.domain_id);
        anra_info.domain_id = NULL;
    }
    if (domain_id) {
        anra_info.domain_id = (uint8_t *)an_malloc_guard(an_strlen(domain_id)+1, 
                                           "AN RA CFG domain_id");
        if (anra_info.domain_id) {
            an_memcpy_guard_s(anra_info.domain_id, an_strlen(domain_id)+1, domain_id, 
                                                       an_strlen(domain_id)+1);
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                      "\n%sDomain Id [%s] is set for the Autonomic Registrar", 
                      an_ra_event, anra_info.domain_id);
        } else {
            return (ANR_CONFIG_ERR_NOT_CONFIG);
        }    
    }
    return (ANR_CONFIG_ERR_NONE);
}

anr_config_err_e
an_anra_set_device_id_prefix (uint8_t *device_id_prefix)
{
   if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                   "\n%sDevice is part of %s, it cannot be configured as"
                   "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
   }

   if (anra_info.device_id_prefix) {
        an_free_guard(anra_info.device_id_prefix);
        anra_info.device_id_prefix = NULL;
   }

   if (device_id_prefix) {
        anra_info.device_id_prefix = (uint8_t *)an_malloc_guard(
                                      an_strlen(device_id_prefix)+1,
                                      "Autonomic Registrar deviceid prefix");
        if (anra_info.device_id_prefix) {
            an_memcpy_guard_s(anra_info.device_id_prefix, 
                            an_strlen(device_id_prefix)+1,
                            device_id_prefix, an_strlen(device_id_prefix)+1);
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAutonomic Registrar's device_id prefixis set to %s",
                         an_ra_event, anra_info.device_id_prefix);
        } else {
            return (ANR_CONFIG_ERR_NOT_CONFIG);
        }
    }

    return (ANR_CONFIG_ERR_UNKNOWN);
}

anr_config_err_e
an_anra_set_ca_type (anr_ca_type_e ca_type)
{
    if (an_anra_is_device_not_ra_and_bootstrapped()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAutonomic Registrar is live, can't change the "
                     "current domain",
                     an_ra_event);
        return (ANR_CONFIG_ERR_LIVE);
    }

    anra_info.ca_type = ca_type;
    if (anra_info.ca_type == ANR_EXTERNAL_CA) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAutonomic Registrar is configured in ra mode to"
                     " connect with external CA",
                     an_ra_event);
    } else if (anra_info.ca_type == ANR_LOCAL_CA) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sAutonomic Registrar is configured in local CA mode ",
                    an_ra_event);
    }

    return (ANR_CONFIG_ERR_NONE);
}

boolean
an_anra_is_external_ca (void)
{
    return (ANR_EXTERNAL_CA == anra_info.ca_type);
}

boolean
an_anra_is_local_ca (void)
{
    return (ANR_LOCAL_CA == anra_info.ca_type);
}

boolean
an_anra_is_ca_configured (void)
{
    return (ANR_NO_CA != anra_info.ca_type);
}

anr_ca_type_e
an_anra_get_ca_type (void)
{
    return (anra_info.ca_type);
}

uint8_t *
an_anra_get_domain_id (void)
{
    return (anra_info.domain_id);
}

uint8_t *
an_anra_get_db_url (void)
{
    return (anra_info.db_url);
}

boolean
an_anra_is_db_url_not_default (void)
{
    return (an_strncmp(an_anra_get_db_url(), AN_REGISTRAR_DEFAULT_DB_URL, 
                    AN_STR_MAX_LEN) != 0);
}

uint8_t *
an_anra_get_ca_url (void)
{
    return (anra_info.ca_url);
}

uint8_t *
an_anra_get_ca_vrf (void)
{
    return (anra_info.vrf_name);
}

anr_config_err_e
an_anra_set_whitelist_filename (void *whitelist_filename)
{
    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sAutonomic Registrar is live, can't change the "
                     "current domain",
                     an_ra_event);
        return (ANR_CONFIG_ERR_LIVE);
    }

    if (anra_info.whitelist_filename) {
        an_free_guard(anra_info.whitelist_filename);
        anra_info.whitelist_filename = NULL;
    }

    if (whitelist_filename != NULL)  {
        anra_info.checkUDI = TRUE;
        anra_info.whitelist_filename = 
                    (uint8_t *)an_malloc_guard(an_strlen(whitelist_filename)+1, 
                                       "AN RA CFG UDI list");
        if(anra_info.whitelist_filename) {
           an_memcpy_guard_s(anra_info.whitelist_filename, an_strlen(whitelist_filename)+1, 
                               whitelist_filename, an_strlen(whitelist_filename)+1);
           DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                        "\n%sAutonomic Registrar Whitelist set to %s", an_ra_db,
                        anra_info.whitelist_filename);
           return (ANR_CONFIG_ERR_NONE);
        }
    } else  {
         DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sWhitelist doesn't exist, setting checkUDI to FALSE",
                     an_ra_event); 
        anra_info.checkUDI = FALSE;
        anra_info.whitelist_filename = NULL; 
    }

    return (ANR_CONFIG_ERR_NOT_CONFIG);
}

uint8_t*
an_anra_get_whitelist_filename (void)
{
    return (anra_info.whitelist_filename);
}

an_addr_t
an_anra_get_registrar_ip (void)
{
    return (anra_info.registrar_ip);
}

uint8_t *
an_anra_get_device_id_prefix (void)
{
    return (anra_info.device_id_prefix);
}

anr_config_err_e
an_anra_shut (void)
{

    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                   "\n%sDevice is part of %s, it cannot be configured as"
                   "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }
    
    if (!an_is_active_rp()) {
        if (!an_anra_is_live_pen_ca()) {
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                   "\n%sAutonomic Registrar is already shut", an_ra_event);
            return (ANR_CONFIG_ERR_NOT_LIVE);
        }
    } else if (!an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                  "\n%sAutonomic Registrar is already shut", an_ra_event);
        return (ANR_CONFIG_ERR_NOT_LIVE);
    }    

    if (!an_system_is_configured()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
               "\n%sAutonomic Registrar shut is held till the system is ready",
               an_ra_event);
        anra_info.state = ANR_INFO_STATE_SHUT_PENDING;
        return (ANR_CONFIG_ERR_PENDING);
    }

    return (ANR_CONFIG_ERR_NONE);
}

void
an_anra_shut_pending (void) {
    an_udi_t my_udi = {};

    if (!an_is_active_rp()) {
        anra_info.state = ANR_INFO_STATE_SHUT;
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                   "\n%sAutonomic Registrar is shut", an_ra_event);
        return ;
    }
    if (an_anra_is_live()) {
        an_timer_stop(&an_anra_cs_check_timer);
        an_anra_cfg_ca_server(ANR_CA_SERVER_COMMAND_SHUT);
    }

    anra_info.state = ANR_INFO_STATE_SHUT;
    
    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sAutonomic Registrar is shut", an_ra_event);

    if (an_get_udi(&my_udi)) {
        an_syslog(AN_SYSLOG_ANRA_DOWN, my_udi.data);
    }

    an_event_anra_shut();
}

anr_config_err_e 
an_anra_live (void)
{
    boolean ret = FALSE;
    an_udi_t udi = {};
    an_mac_addr display_mac[AN_IEEEBYTES*2+1] = {0};
    an_mac_addr service_name_mac[AN_IEEEBYTES*2+1] = {0};
//    uint8_t *anr_id_devicename_delimiter_chk;
//    uint8_t *sys_hname;

    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
             "\n%sDevice is part of %s, it cannot be configured "
             "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    anr_config_err_e err;

    if (!an_anra_is_configured()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
               "\n%sAutonomic Registrar is not configured, cannot unshut it", 
               an_ra_event);
        return (ANR_CONFIG_ERR_NOT_CONFIG);
    }

    if (an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAutonomic Registrar is already live", an_ra_event); 
        return (ANR_CONFIG_ERR_LIVE);
    }

    if (!an_anra_is_minimum_config_done()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
              "\n%sMinimum config required for Autonomic Registrar is not " 
              "done, cannot unshut", an_ra_event); 
        return (ANR_CONFIG_ERR_NOT_CONFIG);
    }
#if 0
    an_get_device_hostname(anr_id_devicename, ANR_MAXHOSTNAMELEN);
    if(an_strlen(anr_id_devicename) > ANR_MAXHOSTNAMELEN) {
       DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAutonomic Registrar hostname is greater than ANR_MAXHOSTNAMELEN "
                     "%d, cannot unshut", an_ra_event, ANR_MAXHOSTNAMELEN);

       return (ANR_CONFIG_ERR_HOSTNAME_LEN);
    }
    

    anr_id_devicename_delimiter_chk = strchr(anr_id_devicename,DEVICE_DOMAIN_NAMES_DELIMITER);
    if (anr_id_devicename_delimiter_chk) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAutonomic Registrar hostname has illegal character "
                     "%c, cannot unshut", an_ra_event, DEVICE_DOMAIN_NAMES_DELIMITER);

        return (ANR_CONFIG_ERR_HOSTNAME_ILLEGAL);
    }

    an_get_device_system_hostname (sys_hname);
    //compare hostname with default hostname and take actions accordingly.
#endif

    if (!an_system_is_configured()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
            "\n%sAutonomic Registrar unshut is held till the system is ready",
            an_ra_event);
        anra_info.state = ANR_INFO_STATE_LIVE_PENDING;
        return (ANR_CONFIG_ERR_PENDING);
    }

    an_get_device_base_mac_addr(an_chassis_mac);
    an_str_convert_mac_addr_hex_to_str(display_mac, an_chassis_mac, 
                             AN_IEEEBYTES, AN_MACADDR_DELIMITER_DEVICE_NAME);
    an_anra_set_mac_address(display_mac);
    //anra_info.device_id_prefix = an_anra_get_mac_address();    
    an_anra_set_device_id_prefix(an_anra_get_mac_address());
    an_str_convert_mac_addr_hex_to_str(service_name_mac, an_chassis_mac, 
                            AN_IEEEBYTES, AN_MACADDR_DELIMITER_SERVICE_NAME);
    an_anr_set_service_name(service_name_mac);

    if (!an_get_udi(&udi)) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
           "\n%sAutonomic Registrar unshut is held till UDI is available",
            an_ra_event);
        anra_info.state = ANR_INFO_STATE_LIVE_PENDING;
        return (ANR_CONFIG_ERR_PENDING);
    }

    if  (anra_info.whitelist_filename) {
        ret = an_anra_read_whitelist_device_db_from_file(
                                anra_info.whitelist_filename);
        if (ret == FALSE) {
            DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,  
                    "\n%sFailed to read whitelist device DB from file %s, " 
                    "continuing with out it", an_ra_db, 
                    anra_info.whitelist_filename);
           err = an_anra_set_whitelist_filename(NULL);
           an_syslog(AN_SYSLOG_ANRA_WHITELIST_FILE_ERROR, 
                     anra_info.whitelist_filename);
           return (ANR_CONFIG_ERR_WHITELIST_FILE);
        }
    }
   
    an_anra_read_accepted_device_db_from_file();
    an_anra_read_quarantine_device_db_from_file();

    anra_info.state = ANR_INFO_STATE_LIVE_PEN_CA;
    return (ANR_CONFIG_ERR_NONE);
}

boolean
an_anra_check_anra_cert_expired (void)
{
    an_cert_t domain_cert = {};
    if (an_tp_exists(AN_DOMAIN_TP_LABEL) &&
        an_get_domain_cert(&domain_cert) && !domain_cert.valid) {
        return (TRUE);
    }
    return (FALSE);
}

void
an_anra_live_pending (void)
{
    an_cert_t domain_cert = {};
    boolean ntp_status = FALSE;
    an_cert_api_ret_enum result;
    uint8_t anr_file[AN_STR_MAX_LEN] = {};
    an_cerrno rc;

    if (!an_is_active_rp()) {
        return;
    }

    if (an_anra_is_shut()) {
        an_anra_cfg_ca_server(ANR_CA_SERVER_COMMAND_UNSHUT);
    } else {
        an_anra_cfg_ca_server(ANR_CA_SERVER_COMMAND_CREATE);

        rc = an_avl_init(&an_anra_quarantine_device_tree, 
                         an_quarantine_device_compare);
        if (CERR_IS_NOTOK(rc)) {
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                    "\n%sAN Registrar Quarantine DB Init Failed", an_ra_event);
        }

        rc = an_avl_init(&an_anra_color_device_tree, 
                         an_anra_color_device_compare);
        if (CERR_IS_NOTOK(rc)) {
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAN Registrar Color DB Init Failed", an_ra_event);
        }

        rc = an_avl_init(&an_accepted_device_tree, an_accepted_device_compare);
        if (CERR_IS_NOTOK(rc)) {
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAN Registrar Accepted DB Init Failed", an_ra_event);
        }
    }    
   
    anra_info.state = ANR_INFO_STATE_LIVE;
    an_timer_init(&an_anra_cs_check_timer, AN_TIMER_TYPE_ANR_CS_CHECK, 
                  NULL, FALSE);
    an_nbr_db_walk(an_acp_remove_clock_sync_with_nbrs, NULL);
    an_acp_remove_clock_sync_with_server(g_ntp_ra_address);
	ntp_status = an_ntp_add_remove_master(AN_NTP_MASTER_STRATUM, FALSE);
	if (TRUE == ntp_status) {
		DEBUG_AN_LOG(AN_LOG_SRVC_NTP,  AN_DEBUG_MODERATE, NULL,
					 "\n%sNTP enabled locally", an_srvc_ntp);
	} else {
		DEBUG_AN_LOG(AN_LOG_SRVC_NTP,  AN_DEBUG_MODERATE, NULL,
					"\n%sFailed to enable NTP locally", an_srvc_ntp);
	}

    /* Check if the device is in the same domain as the ANR under creation
     * or resumption. This is TRUE if one of the following statements is TRUE.
     *      1. AN-DOMAIN-TP Does not exit (device is not in any domain)
     *      2. device-id is not there     (device is not in any domain)
     *      3. domain-id is not there     (device is not in any domain)
     *      4. domain-cert is not there    (device is not in any domain)
     */
    if (!an_tp_exists(AN_DOMAIN_TP_LABEL) ||
        !an_get_device_id() || !an_get_domain_id() || 
        !an_get_domain_cert(&domain_cert)) {

         if (an_anra_cs_up()) {

            an_snprintf(anr_file, AN_STR_MAX_LEN, "%s%s_%s",
                         an_anra_get_db_url(), ANRA_CS_TP_LABEL, "00001.pem");
            an_file_copy_to_stby_later(anr_file);
            an_snprintf(anr_file, AN_STR_MAX_LEN, "%s%s.%s",
                         an_anra_get_db_url(), ANRA_CS_TP_LABEL, "crl");
            an_file_copy_to_stby_later(anr_file);

            an_anra_bootstrap_thyself();

            an_syslog(AN_SYSLOG_ANRA_UP, an_get_device_id(), 
                      an_get_domain_id());

            an_event_anra_up_locally();

            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%sAutonomic Registrar is Live", an_ra_event);
            //topo_disc_initiate();
        } else {
            an_timer_start(&an_anra_cs_check_timer, AN_ANRA_CS_CHECK_INTERVAL);
        }
    } else if (an_anra_check_anra_cert_expired()) {
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%sAutonomic Registrar certificate expired- "
                        "will bootstrap iself", an_ra_event);
            an_anra_bootstrap_thyself();
    } else { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%sAutonomic Registrar coming up after "
                        "save and reload", an_ra_event);
        an_anra_set_device_id(an_get_device_id());
        an_anra_set_local_anra_ip();
        an_event_anra_up_locally();
        //Sometimes ANRA IP get computed later after ACP is 
        //initialized in save and reload
        result = an_cert_config_trustpoint(an_anra_get_registrar_ip());
        if (result != AN_CERT_API_SUCCESS)
        {
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_SEVERE, NULL,
                 "\n%sError in configuring Re-enrollment params on "
                 "trustpoint %s", an_ra_event, AN_DOMAIN_TP_LABEL);
        }
    }

}
 
anr_config_err_e
an_anra_delete (void)
{
    anr_config_err_e anr_config_err = ANR_CONFIG_ERR_UNKNOWN;

    if (!an_anra_is_configured()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
               "\n%sAutonomic Registrar is not configured, cannot delete it", 
               an_ra_event);
        return (ANR_CONFIG_ERR_NONE);
    }

    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                  "\n%sDevice is part of %s, it cannot be configured "
                  "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (!an_is_active_rp()) {
        if (an_anra_is_live_pen_ca()) {
            anr_config_err = an_anra_shut();
        }
    } else if (an_anra_is_live()) {
        anr_config_err = an_anra_shut();
    }

    if (anr_config_err == ANR_CONFIG_ERR_NONE) {
        an_process_call_no_registrar(ANR_CONFIG_ERR_NONE);
    } else {
        an_process_call_no_registrar(!ANR_CONFIG_ERR_NONE);
    }

    return (ANR_CONFIG_ERR_NONE);
}

void
an_anra_delete_pending (void) 
{
    an_anra_set_domain_id(NULL);
    an_anra_set_device_id_prefix(NULL);
    an_anra_set_device_id(NULL);
    an_anra_set_ca_url(NULL);
    an_anra_set_db_url(AN_REGISTRAR_DEFAULT_DB_URL);
    an_anra_set_ca_vrf(NULL);
    an_anra_set_ca_type(ANR_NO_CA);
    an_anra_set_device_id_prefix(NULL);
    an_anra_set_whitelist_filename(NULL);
    an_anra_set_mac_address(NULL);
    an_anr_set_service_name(NULL);
    if (an_is_active_rp()) {
        an_anra_set_local_anra_ip();
        an_anra_cfg_ca_server(ANR_CA_SERVER_COMMAND_DELETE);
    }
    an_anra_init();

    anra_info.state = ANR_INFO_STATE_NONE;

    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                  "\n%sAutonomic Registrar is deleted", an_ra_event);
    an_event_registrar_uninit();

    an_avl_uninit(&an_accepted_device_tree);
    an_avl_uninit(&an_anra_color_device_tree);
    an_avl_uninit(&an_anra_quarantine_device_tree);

}

/*************************** End of ANRA Configuration Section **************/

void
an_anra_init (void)
{
    uint8_t file[AN_STR_MAX_LEN] = {};

    an_accepted_device_db_init();
    an_anra_color_device_db_init(0); 
    an_anra_quarantine_device_db_init();

    an_anra_init_device_suffix_pool(0);

    an_snprintf(file, AN_STR_MAX_LEN, "%s%s", an_anra_get_db_url(), 
                        AN_REGISTRAR_ACCEPTED_DEVICE_FILENAME);
    an_file_delete(file);

    an_snprintf(file, AN_STR_MAX_LEN, "%s%s", an_anra_get_db_url(), 
                        AN_REGISTRAR_QUARANTINE_DEVICE_FILENAME);
    an_file_delete(file);

    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAutonomic Registrar is initialized", an_ra_event);
}

void
an_anra_uninit (void)
{
    an_anra_init();
}

#if 0
void 
an_anra_generate_domain_hash (char* hash) 
{
    an_cert_t cert;
    CertAttributeRecord *pubkey_der;
    int pki_err;
    uint32_t pubkeylen;
    char* pubkey;
    SHA1_CTX ctx;

    cert = an_get_ca_cert();
    if (!cert.data) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                "\n%sFailed to retreive Autonomic Register device certificate", 
                an_ra_event);
        return;
    }
    pki_err = PKI_GetCertAttribute(PKI_API_NO_SESSION, 
                            CF_CERT_PUBLIC_KEY, cert.data, &pubkey_der);
    if (pki_err == CRYPTO_PKI_API_SUCCESS) {
        pubkeylen = pubkey_der->attribute_len; 
        pubkey = pubkey_der->attribute_value;
        SHA1Init(&ctx);
        SHA1Update(&ctx, pubkey, pubkeylen);
        SHA1Final(hash, &ctx);
        PKI_cert_attribute_free(pubkey_der);
        return;
    } else {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to generate domain hash", an_ra_event);
        return;
    }
}
#endif

anr_config_err_e
an_anra_allow_quarantine_device (an_udi_t quarantine_udi)
{
    an_anra_quarantine_device_t *quarantine_device = NULL;
    an_anra_color_device_t *whitelist_device = NULL;

    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                  "\n%sDevice is part of %s, it cannot be configured "
                  "as Autonomic Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (!an_udi_is_format_valid((an_udi_t *)&quarantine_udi)) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT,AN_DEBUG_MODERATE, NULL, 
                     "\n%sInvalid UDI %s entered ",
                     an_ra_event, quarantine_udi.data);
        return (ANR_CONFIG_ERR_UDI_INVALID);
    }      

    whitelist_device = an_anra_color_device_db_search(quarantine_udi);
    if (!whitelist_device) {
        whitelist_device = an_anra_color_device_alloc();
        whitelist_device->udi.data =
          (uint8_t *)an_malloc_guard(quarantine_udi.len, 
                                    "AN RA Whitelist Device UDI");
        if (!whitelist_device->udi.data) {
            an_anra_color_device_free(whitelist_device);
            return (ANR_CONFIG_ERR_UNKNOWN);
        }
        an_memcpy_guard_s(whitelist_device->udi.data, quarantine_udi.len, 
                                     quarantine_udi.data, quarantine_udi.len);
        whitelist_device->udi.len = quarantine_udi.len;
        whitelist_device->label = AN_QUARANTINE_TO_WHITELIST_DEVICE;
        if (!an_anra_color_device_db_insert(whitelist_device)) {
            an_anra_color_device_free(whitelist_device);
        }
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sAdded quarantined device ID [%s] of Len [%d] " 
                     "to whitelist", an_ra_db, quarantine_udi.data, 
                     quarantine_udi.len); 
    } else {
       return (ANR_CONFIG_ERR_DEVICE_ACCEPTED);
    }


    quarantine_device = an_anra_quarantine_device_db_search(quarantine_udi);
    if (quarantine_device)    {
        an_anra_trigger_bs_enroll_quarantine_message(quarantine_udi,
                            quarantine_device->anproxy, 
                            quarantine_device->iptable);
        an_anra_quarantine_device_db_remove(quarantine_device);
        an_anra_quarantine_device_free(quarantine_device);
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sRemoving quarantined device ID [%s] of Len [%d] " 
                     "to whitelist", an_ra_db, quarantine_udi.data, 
                     quarantine_udi.len);

        an_anra_write_full_quarantine_device_db_to_file();
    }
    
    return (ANR_CONFIG_ERR_NONE);
}

anr_config_err_e
an_anra_is_device_accepted (an_udi_t quarantine_udi)
{
    an_accepted_device_t *member = NULL;

    if (!an_udi_is_format_valid((an_udi_t *)&quarantine_udi)) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                 "\n%sInvalid UDI %s entered", an_ra_db, quarantine_udi.data);
        return (ANR_CONFIG_ERR_UDI_INVALID);
    }

    member = an_accepted_device_db_search(quarantine_udi);
    if (NULL == member) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                    "\n%sDevice (%s) is not found in Accepted device list",
                    an_ra_db, quarantine_udi.data);
        return (ANR_CONFIG_ERR_NONE);
    } else {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                    "\n%sDevice (%s) is found in Accepted device list",
                    an_ra_db, quarantine_udi.data);                               
    }
    return (ANR_CONFIG_ERR_DEVICE_ACCEPTED);
}

anr_config_err_e
an_anra_remove_device_from_whitelist (an_udi_t quarantine_udi)
{
     an_anra_color_device_t *whitelist_device = NULL;
     boolean result = FALSE;

     whitelist_device = an_anra_color_device_db_search(quarantine_udi);
     if (!whitelist_device) {
         DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice (%s) is not found in whitelist",
                     an_ra_db, quarantine_udi.data);
         return (ANR_CONFIG_ERR_UNKNOWN);
     } else {
        if (whitelist_device->label == AN_QUARANTINE_TO_WHITELIST_DEVICE) {
            result = an_anra_color_device_db_remove(whitelist_device);
            an_anra_color_device_free(whitelist_device);

            if (FALSE == result) {
                return (ANR_CONFIG_ERR_UNKNOWN);
            }
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice (%s) is removed from whitelist",
                     an_ra_event, quarantine_udi.data);
        }
    }

    return (ANR_CONFIG_ERR_NONE);
}

void 
an_anra_quarantine_device (an_msg_package *message)
{
   an_anra_quarantine_device_t *quarantine_device = NULL;

   quarantine_device = an_anra_quarantine_device_db_search(message->udi);

   if (quarantine_device == NULL) {
       quarantine_device = an_anra_quarantine_device_alloc();
       quarantine_device->udi.data =
           (uint8_t *)an_malloc_guard(message->udi.len,
                                      "AN RA Quarantine Device UDI");
       if (!quarantine_device->udi.data) {
           an_anra_quarantine_device_free(quarantine_device);
           return;
       }

       an_memcpy_guard_s(quarantine_device->udi.data, message->udi.len,
                                        message->udi.data, message->udi.len);

       quarantine_device->udi.len = message->udi.len;
       quarantine_device->iptable = message->iptable;
       quarantine_device->anproxy = message->dest;//should be to dst

       if (!an_anra_quarantine_device_db_insert(quarantine_device)) {
           an_anra_quarantine_device_free(quarantine_device);
           return;
       }

       an_write_device_from_db_to_local_file(quarantine_device, 
                                    AN_QUARANTINE_FILE_IDENTIFIER);
   }
}

void 
an_anra_udi_available (void)
{
    anr_config_err_e anr_config_err = ANR_CONFIG_ERR_NONE;    
    an_cerrno rc = EOK;
    int indicator;

    if (!an_anra_is_configured()) {
        return;
    }
    
    if (!an_system_is_configured()) {
        return;
    }

    rc = an_avl_init(&an_anra_quarantine_device_tree, 
                         an_quarantine_device_compare);
    if (CERR_IS_NOTOK(rc)) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAN Registrar Quarantine DB Init Failed", an_ra_event);
    }

    rc = an_avl_init(&an_anra_color_device_tree, 
                         an_anra_color_device_compare);
    if (CERR_IS_NOTOK(rc)) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAN Registrar Color DB Init Failed", an_ra_event);
    }

    rc = an_avl_init(&an_accepted_device_tree, an_accepted_device_compare);
    if (CERR_IS_NOTOK(rc)) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAN Registrar Accepted DB Init Failed", an_ra_event);
    }

    switch (anra_info.state) {
    case ANR_INFO_STATE_LIVE_PENDING:
        anr_config_err = an_anra_live();
        if (anr_config_err == ANR_CONFIG_ERR_NONE) {
            an_process_call();
        }

    break;
    
    case ANR_INFO_STATE_SHUT_PENDING:
        anr_config_err = an_anra_shut();
        if (anr_config_err == ANR_CONFIG_ERR_NONE) {
             an_process_call_shut();
        }

    break;

    case ANR_INFO_STATE_LIVE:
        an_memcmp_s(anra_info.domain_id, an_strlen(anra_info.domain_id)+1, 
            an_get_domain_id(), an_strlen(anra_info.domain_id)+1, &indicator);
        if (!an_get_device_id() || !an_get_domain_id() || indicator) {
             if (an_anra_cs_up()) {
                an_anra_bootstrap_thyself();
             }
        }
    break;

    default:
        return;
    break;
    }
}

/*************************** ANRA - Mesages Section ******************************/

void
an_anra_trigger_bs_enroll_quarantine_message (an_udi_t invitee_udi,
            an_addr_t proxy_addr,
            an_iptable_t iptable)
{
    an_msg_package *message = NULL;
    
    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                 "\n%sTriggering Nbr Enroll message to quarantine device", 
                 an_bs_pak);
    
    if (!invitee_udi.data || !invitee_udi.len) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sInvitee UDI is NULL", an_bs_pak);
        return;
    }

    message = an_msg_mgr_get_empty_message_package();   
    if (!message) {
        return;
    }   

    message->src     = an_anra_get_registrar_ip();
    message->iptable = iptable;
    message->dest    = proxy_addr;
    
    an_msg_mgr_init_header(message, AN_PROTO_ACP, 
                           AN_MSG_BS_ENROLL_QUARANTINE);
    
    /* UDI */
    message->udi.len  = invitee_udi.len;
    message->udi.data = 
        (uint8_t *)an_malloc_guard(invitee_udi.len, "AN MSG UDI");
    if (!message->udi.data) {
        an_msg_mgr_free_message_package(message);
        return;
    }        
    an_memcpy_guard_s(message->udi.data, message->udi.len, invitee_udi.data,
                                                             invitee_udi.len);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);
    
    /* Device ID */
    message->device_id = NULL;

    /* Domain ID */
    message->domain_id = NULL;

    /* ANRA IP Addr */
    message->anra_ipaddr = an_anra_get_registrar_ip();
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_ANRA_IPADDR);

    an_msg_mgr_send_message(message);
}

void
an_anra_trigger_bs_reject_message (an_udi_t invitee_udi, 
                                   an_addr_t proxy_addr, 
                                   an_iptable_t iptable)
{
    an_msg_package *message = NULL;

    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                 "\n%sAutonomic Registrar triggering Nbr Bootstrap "
                 "Reject message to the quarantined device", an_bs_pak);
    
    if (!invitee_udi.data || !invitee_udi.len) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sInvitee UDI is NULL", an_bs_pak);
        return;
    }

    message = an_msg_mgr_get_empty_message_package();   
    if (!message) {
        return;
    }   

    message->src     = an_anra_get_registrar_ip();
    message->iptable = iptable;
    message->dest    = proxy_addr;

    an_msg_mgr_init_header(message, AN_PROTO_ACP, 
                           AN_MSG_BS_REJECT);
    /* UDI */
    message->udi.len  = invitee_udi.len;
    message->udi.data = 
        (uint8_t *)an_malloc_guard(invitee_udi.len, "AN MSG UDI");
    if (!message->udi.data) {
        an_msg_mgr_free_message_package(message);
        return;
    } 
    an_memcpy_guard_s(message->udi.data, message->udi.len, invitee_udi.data,
                                                         invitee_udi.len);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);

    /* Device ID */
    message->device_id = NULL;

    /* Domain ID */
    message->domain_id = NULL;

    /* ANRA IP Addr */
    message->anra_ipaddr = an_anra_get_registrar_ip();
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_ANRA_IPADDR);

    an_msg_mgr_send_message(message);
}

void
an_anra_trigger_bs_invite_message (an_udi_t invitee_udi, an_addr_t proxy_addr,
                                   an_iptable_t iptable, an_sign_t* masa_sign)
{
    an_msg_package *message = NULL;
    uint8_t *device_id = NULL, *domain_id = NULL;
    an_cert_t anra_cert = {};
    an_cert_t ca_cert = {};
    an_cert_t domain_cert = {};
    an_cert_api_ret_enum result;
    boolean result_get_cert = FALSE;
    an_mac_addr display_mac[AN_IEEEBYTES*2+1] = {0};
    an_udi_t my_udi = {};
    int indicator;

    if (!invitee_udi.data || !invitee_udi.len) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "%sNull Input Params to send Bootstrap Invite Message", 
                     an_bs_pak);
        return;
    }
    
    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
              "\n%sAutonomic Registrar sending Nbr Bootstrap Invite message", 
               an_bs_pak);
    message = an_msg_mgr_get_empty_message_package();   
    if (!message) {
        return;
    }   

    message->src = an_anra_get_registrar_ip();
    message->iptable = iptable;
    message->dest = proxy_addr;

    an_msg_mgr_init_header(message, AN_PROTO_ACP, 
                           AN_MSG_BS_INVITE);
    /* UDI */
    message->udi.len = invitee_udi.len;
    message->udi.data = (uint8_t *)an_malloc_guard(invitee_udi.len, 
                                   "AN MSG UDI");
    if (!message->udi.data) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sBootstrap Invite message has Null udi data", 
                     an_bs_pak);
        an_msg_mgr_free_message_package(message);
        return;
    }
    an_memcpy_guard_s(message->udi.data, message->udi.len, invitee_udi.data, 
                                                            invitee_udi.len);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);

    /* Device ID */
    device_id = an_anra_add_assign_member_device_id(invitee_udi);    
    message->device_id = (uint8_t *)an_malloc_guard(an_strlen(device_id)+1, 
                                                    "AN MSG Device ID ANRA");
    if (!message->device_id) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sBootstrap Invite message has Null device Id", 
                     an_bs_pak);
        an_msg_mgr_free_message_package(message);
        return;
    }
    an_memcpy_guard_s(message->device_id, an_strlen(device_id)+1, device_id, 
                                                    an_strlen(device_id)+1); 
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DEVICE_ID);

    /* Domain ID */
    domain_id = anra_info.domain_id;
    message->domain_id = (uint8_t *)an_malloc_guard(an_strlen(domain_id)+1, 
                                                    "AN MSG Domain ID");
    if (!message->domain_id) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                "\n%sBootstap Invite message has Null Domain Id", an_bs_pak);
        an_msg_mgr_free_message_package(message);
        return;
    }

    an_memcpy_guard_s(message->domain_id, an_strlen(domain_id)+1, domain_id, 
                                          an_strlen(domain_id)+1);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DOMAIN_ID);

    /* ANRA IP Addr */
    message->anra_ipaddr = an_anra_get_registrar_ip();
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_ANRA_IPADDR);

    /* ANRA Cert */
    result_get_cert = an_get_domain_cert(&domain_cert);
    if (!an_get_udi(&my_udi)) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                   "\n%sFailed to trigger BS invite- unable to read my UDI",
                   an_bs_pak); 
        an_msg_mgr_free_message_package(message);
        return;
    } 
    an_memcmp_s(message->udi.data, message->udi.len, my_udi.data, 
                message->udi.len, &indicator);
    
    if (result_get_cert && !domain_cert.valid) {
        /*If BS invite is for another device- if ANRA cert is invalid- dont
          send BS invite*/
        if ((message->udi.len != my_udi.len) && indicator) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                   "\n%sANRA cert invalid- not sending "
                   "Bootstrap Invite Message to device", 
                   an_bs_pak);
            an_msg_mgr_free_message_package(message);
            return;
        }
    }

    if (an_tp_exists(AN_DOMAIN_TP_LABEL) && result_get_cert 
        && domain_cert.valid && indicator) {

        result = an_cert_get_device_cert_from_tp(AN_DOMAIN_TP_LABEL, 
                                                 &anra_cert);
        if (result != AN_CERT_API_SUCCESS) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sWhile triggering Bootstrap Invite Message, %s",
                     an_bs_pak, an_cert_enum_get_string(result));
            an_msg_mgr_free_message_package(message);
            return;
        }
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sObtained ANRA Cert from Trustpoint %s", an_bs_pak, 
                     "AN_DOMAIN_TP_LABEL");

        message->anra_cert.len = anra_cert.len;
        message->anra_cert.data = (uint8_t *)an_malloc_guard(anra_cert.len, 
                                                    "AN MSG ANRA Cert");
        if (!message->anra_cert.data) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sBootstrap Invite message has Null "
                     "Autonomic Registrar Cert Data", an_bs_pak);
            an_msg_mgr_free_message_package(message);
            return;
        }
        an_memcpy_guard_s(message->anra_cert.data, message->anra_cert.len, 
                                              anra_cert.data, anra_cert.len);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_ANRA_CERT);

    }

    /* CA Cert */
    result = an_cert_get_ca_cert_from_tp(ANRA_CS_TP_LABEL, &ca_cert);
    if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sWhile triggering Bootstrap Invite Message, %s",
                     an_bs_pak, an_cert_enum_get_string(result));
        an_msg_mgr_free_message_package(message);
        return;
    }
    
    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sObtained CA Cert from Trustpoint %s", an_bs_pak, 
                     "AN_CS_TP_LABEL");

    message->ca_cert.len = ca_cert.len;
    message->ca_cert.data = (uint8_t *)an_malloc_guard(ca_cert.len, 
                                                    "AN MSG CA Cert");
    if (!message->ca_cert.data) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sBootstrap Invite message has NULL CA "
                     "Cert Data", an_bs_pak);
        an_msg_mgr_free_message_package(message);
        return;
    }
    an_memcpy_guard_s(message->ca_cert.data, message->ca_cert.len, 
                      ca_cert.data, ca_cert.len);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_CA_CERT);

    /* MASA Signature */
    if (masa_sign) {
        message->masa_sign.data = (uint8_t*)an_malloc(masa_sign->len, "Masa Sign");
        an_memcpy_s(message->masa_sign.data, masa_sign->len, masa_sign->data, masa_sign->len);
        message->masa_sign.len = masa_sign->len;
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_MASA_SIGN);

    } else {
        message->masa_sign.data = NULL;
        message->masa_sign.len = 0;
        AN_CLEAR_BIT_FLAGS(message->interest, AN_MSG_INT_MASA_SIGN);
    }
   
    if (!an_get_device_base_mac_addr(an_chassis_mac)) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sUnable to get device MAC addr", an_bs_pak);
        an_msg_mgr_free_message_package(message);
        return;
    }
    if (!an_str_convert_mac_addr_hex_to_str(display_mac, an_chassis_mac, 
                          AN_IEEEBYTES, AN_MACADDR_DELIMITER_DEVICE_NAME) ) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sUnable to get device MAC addr", an_bs_pak);
        an_msg_mgr_free_message_package(message);
        return;
    }
    message->macaddress = (an_mac_addr *)an_malloc_guard(
                                         an_strlen(display_mac)+1,
                                         "AN MSG CA Cert");
    if (!message->macaddress) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                   "\n%sBootstrap Invite message malloc failed for mac addr", 
                   an_bs_pak);
        an_msg_mgr_free_message_package(message);
        return;
    }
    an_memcpy_guard_s(message->macaddress, an_strlen(display_mac)+1,
                      display_mac, an_strlen(display_mac)+1);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_ANR_ID);


    if (an_tp_exists(AN_DOMAIN_TP_LABEL) &&  result_get_cert
        && domain_cert.valid && indicator) {
        /* ANRA Signature */
        result = an_msg_mgr_add_anra_signature(message);
        AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_ANRA_SIGN);
    }
    an_msg_mgr_send_message(message);
}

void
an_anra_trigger_bs_response_message (an_cert_t *cert, an_udi_t dest_udi, 
                               an_addr_t proxy_device, an_iptable_t iptable)
{

    an_msg_package *bs_response = NULL;

    if (!cert->data) {
        return;
    }
    
    bs_response = an_msg_mgr_get_empty_message_package();   
    if (!bs_response) {
        return;
    }   

    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                 "\n%sAutonomic Registrar sending BS Response Message "
                 " on receiving device certificate of length %d",  
                 an_bs_pak, cert->len);

    an_msg_mgr_init_header(bs_response, AN_PROTO_ACP, 
                           AN_MSG_BS_RESPONSE);

    /* UDI */
    bs_response->udi.len  = dest_udi.len;
    bs_response->udi.data =
        (uint8_t *)an_malloc_guard(dest_udi.len, "AN MSG UDI");
    if (!bs_response->udi.data) {
        an_msg_mgr_free_message_package(bs_response);
        return;
    }
    an_memcpy_guard_s(bs_response->udi.data, bs_response->udi.len, 
                      dest_udi.data, dest_udi.len);
    AN_SET_BIT_FLAGS(bs_response->interest, AN_MSG_INT_UDI);

    bs_response->domain_cert.len = cert->len;
    bs_response->domain_cert.data = (uint8_t *)an_malloc_guard(
                        bs_response->domain_cert.len, "AN MSG Domain Cert");
    bs_response->domain_cert.valid = cert->valid;
    if (!bs_response->domain_cert.data) {
        an_msg_mgr_free_message_package(bs_response);
        return;
    } 
    
    an_memcpy_guard_s(bs_response->domain_cert.data, bs_response->domain_cert.len,
                                                         cert->data, cert->len);
    AN_SET_BIT_FLAGS(bs_response->interest, AN_MSG_INT_DOMAIN_CERT);

    bs_response->src = an_anra_get_registrar_ip();
    bs_response->dest = proxy_device;
    bs_response->iptable = iptable;
    bs_response->ifhndl = 0;
    an_msg_mgr_send_message(bs_response); 
}

void
an_anra_incoming_nbr_connect_message (an_msg_package *message)
{
    an_anra_color_device_t *whitelist_device = NULL;

    uint8_t *my_domain_id = NULL;

    an_udi_t my_udi = {};

    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                 "\n%sAutonomic Registrar recieved Nbr Connect Message", 
                 an_bs_pak);
    
    if (!an_get_udi(&my_udi)) {
        an_msg_mgr_free_message_package(message);
        return;
    }

    if (!message || !message->udi.data || !message->udi.len) {
        an_msg_mgr_free_message_package(message);
        return;
    }

    if ((message->header.msg_type != AN_MSG_NBR_CONNECT) &&
        (message->header.msg_type != AN_MSG_NBR_RECONNECT)) {
        an_msg_mgr_free_message_package(message);
        return;
    }
    
    my_domain_id = an_get_domain_id();

    if (!an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sRecieved Nbr Connect, "
                     "but i'm not the Autonomic Registrar, "
                     "Ignoring it", an_bs_pak);
        an_msg_mgr_free_message_package(message);
        return;
    }

    /* Validate device sUDI, if it is there*/
    if (message->sudi.data && message->sudi.len) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sDevice %s has Sudi, Validating it",
                     an_bs_pak, message->udi.data);

        if (!an_cert_validate_override_revoke_check(&message->sudi, 
                                                    AN_LOG_BS_PACKET)) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                         "\n%sDevice Sudi is Invalid, Ignore the device", 
                         an_bs_pak);
            an_msg_mgr_free_message_package(message);
            return;
        } else {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                         "\n%sDevice Sudi is Valid", an_bs_pak);
        }
    }
    if (anra_info.checkUDI == TRUE) {
        /* Validate the device against the whitelist */
        whitelist_device = an_anra_color_device_db_search(message->udi);
        if (whitelist_device) {
            if(whitelist_device->label == AN_WHITELIST_DEVICE) {
                DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                       "\n%sAutonomic Registrar found UDI [%s] in the "
                       "whitelist DB, verifying device with MASA", an_ra_db, 
                       message->udi.data);
            } else if(whitelist_device->label == 
                                AN_QUARANTINE_TO_WHITELIST_DEVICE) {
                //Override MASA check, trigger bs invite
                DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                         "\n%sAutonomic Registrar triggering Bootstrap Invite "
                         "without checking MASA verification", an_bs_pak);
                an_anra_trigger_bs_invite_message(message->udi, 
                                 message->src, an_get_iptable(), NULL);     
 
                an_msg_mgr_free_message_package(message);
                return; 
            }
        } else {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\nUdi [%s] not found in the Whitelist, "
                     "Autonomic Registrar triggers Boostrap Reject "
                     "Message to it", 
                     an_bs_pak, message->udi.data);

            an_syslog(AN_SYSLOG_DEVICE_NOT_ALLOWED,
                            message->udi.data,my_domain_id); 
             
            an_anra_quarantine_device(message);

            an_anra_trigger_bs_reject_message(message->udi,
                message->src, an_get_iptable());
            an_msg_mgr_free_message_package(message);
            return;
        }
    }
    whitelist_device = an_anra_color_device_db_search(message->udi);
    if (whitelist_device) {
        if (whitelist_device->label == 
                AN_QUARANTINE_TO_WHITELIST_DEVICE) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                          "\n%sTriggering BS Invite without Checking MASA "
                          "Verification", an_bs_pak);
            an_anra_trigger_bs_invite_message(message->udi, 
                message->src, an_get_iptable(), NULL);     
            an_msg_mgr_free_message_package(message);

            return;
        }
    }
    an_msg_mgr_free_message_package(message);
}

void
an_anra_incoming_nbr_join_message (an_msg_package *message)
{
    if (!message) {
        return;
    }

    if (!message->header.msg_type != AN_MSG_NBR_JOIN) {
        return;
    }
    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                 "\nDevice with UDI [%s] joined the AN cloud", 
                 an_bs_pak, message->udi.data);
    return;
}

void
an_anra_incoming_nbr_leave_mesage (an_msg_package *message)
{
    return;
}

void
an_anra_incoming_nbr_lost_mesage (an_msg_package *message)
{
    return;
}

void
an_anra_incoming_nbr_modify_mesage (an_msg_package *message)
{
    return;
}

void
an_anra_incoming_bs_request_message (an_msg_package *bs_request_msg)
{
    an_cert_t cert = {};
    an_accepted_device_t *anra_member = NULL;
    an_cert_api_ret_enum result;

    if (!bs_request_msg || !bs_request_msg->udi.data || !bs_request_msg->udi.len) {
        an_msg_mgr_free_message_package(bs_request_msg);
        return;
    }

    if (an_anra_is_live()) {

        anra_member = an_accepted_device_db_search(bs_request_msg->udi);
        if (anra_member) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                    "\n%sValidating Udi [%s], "
                    "Autonomic Registrar now triggering "
                    "Device Cert Enrollment", an_bs_pak, bs_request_msg->udi.data);

            result = an_cert_enroll(&bs_request_msg->cert_request,      
                                    &bs_request_msg->cert_req_sign,
                                    &bs_request_msg->signed_cert_request,
                                    &bs_request_msg->public_key, &cert,
                                    bs_request_msg->udi, bs_request_msg->src,
                                    bs_request_msg->iptable);
            if (result == AN_CERT_ENROLL_SUCCESS) {
                //Got certificate immediately
                if (!cert.data || !cert.len) {
                    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                             "\n%sdevice cert Enrollment returned %s", an_bs_pak, 
                             an_cert_enum_get_string(result));
                }else   {
                    an_anra_notify_cert_enrollment_done(&cert, bs_request_msg->udi,
                                                bs_request_msg->src, 
                                                bs_request_msg->iptable);
                    if (cert.data) {
                        an_free_guard(cert.data);
                    }
                }                    
            }
            an_msg_mgr_free_message_package(bs_request_msg);
            return;
        } else { //Not an accepted device
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sUdi[%s] not found in the Accepted Device DB, "   
                     "hence Autonomic Registrar not triggering "
                     "device cert Enrollment",
                     an_bs_pak, bs_request_msg->udi.data); 
            an_msg_mgr_free_message_package(bs_request_msg);
            return;
        }
    } else {
        //I am not ANRA
        if (!an_bs_forward_message_to_anra(bs_request_msg)) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                         "\n%sI'm not Autonomic Registrar and "
                         "not able to forward "
                         "the Message[%s] to Autonomic Registrar", an_bs_pak, 
                         an_get_msg_name(bs_request_msg->header.msg_type));
            an_msg_mgr_free_message_package(bs_request_msg);
            return;
        }
    }
}

/*
void an_rpl_enable (parseinfo *csb)
{
   an_routing_ospf = 0;
}

void an_ospf_enable (parseinfo *csb)
{
   an_routing_ospf = 1;
}
*/

an_addr_t
an_anr_get_ip_from_srvc_db (void)
{
    an_addr_t anr_address = AN_ADDR_ZERO;
    return (anr_address);
}

