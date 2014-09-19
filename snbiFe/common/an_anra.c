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

extern boolean an_anra_cs_up(void);
extern an_avl_tree an_accepted_device_tree;
extern an_avl_tree an_anra_color_device_tree;
extern an_avl_tree an_anra_quarantine_device_tree;
an_avl_compare_e an_quarantine_device_compare(an_avl_node_t *node1, an_avl_node_t *node2);
an_avl_compare_e an_accepted_device_compare(an_avl_node_t *node1, an_avl_node_t *node2);
an_avl_compare_e an_anra_color_device_compare(an_avl_node_t *node1, an_avl_node_t *node2);

#define ANRA_DEVICE_SUFFIX_POOL_SIZE 128
#define ANR_MAX_FILE_ENTRIES 128
#define ANRA_MAX_WORD_LEN 128
#define ANRA_MAX_LINE_LEN 128
#define ANRA_MAX_UDI_LEN 128

//#define AN_REGISTRAR_SUFFIX_POOL_INDEX_FLENAME "nvram:anr_sfx.an"
#define AN_REGISTRAR_ACCEPTED_DEVICE_FLENAME "nvram:ANR_ACC.an"
#define AN_REGISTRAR_QUARANTINE_DEVICE_FLENAME "nvram:ANR_QUA.an"
#define AN_REGISTRAR_DEVICE_ID_PREFIX "Router-"

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
    "ANR Not Configured",
    "ANR in Configuration",
    "ANR Shut",
    "ANR Shut Pending",
    "ANR Live",
    "ANR Unshut Pending",
    "ANR CA Live Pending",
};

typedef struct anra_info_t_ {
    anr_info_state_e state;
    uint8_t *domain_id;
    uint8_t *device_id;
    uint8_t *device_id_prefix;
    uint8_t *whitelist_filename;
    boolean checkUDI;
    an_addr_t registrar_ip;
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
    uint8_t *file = AN_REGISTRAR_ACCEPTED_DEVICE_FLENAME;
    an_file_api_ret_enum retval;

    if (!accepted_device) {
        return (FALSE);
    }

    fd = an_file_open(file, AN_FOF_WRITE_ONLY | AN_FOF_APPEND);
    if (!an_file_descr_is_valid(fd)) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL,
                     "\n%sFailed to open the file %s", an_ra_db, file);
        return (FALSE);
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
    an_file_close(fd);
    an_file_copy_to_standby(file);
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
    uint8_t *file = AN_REGISTRAR_QUARANTINE_DEVICE_FLENAME;
    an_file_api_ret_enum retval;

    if (!quarantine_device) {
        return (FALSE);
    }

    fd = an_file_open(file, AN_FOF_WRITE_ONLY | AN_FOF_APPEND);
    if (!an_file_descr_is_valid(fd)) {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sFailed to open the file %s", an_ra_db, file);
        return (FALSE);
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
    an_file_close(fd);
    return (TRUE);
}

an_walk_e
an_anra_write_full_quarantine_device_db_cb (an_avl_node_t *node, void *args)
{
    an_file_descr_t *fd = NULL;

    if (!node || !args) {
        return (AN_WALK_FAIL);
    }

    fd = (an_file_descr_t *)args;
    
    if (an_anra_write_quarantine_device_to_opened_file(*fd, 
                          (an_anra_quarantine_device_t *)node)) {
        return (AN_WALK_SUCCESS);
    } else {
        return (AN_WALK_FAIL);
    }
}

boolean
an_anra_write_full_quarantine_device_db_to_file (void)
{
    an_file_descr_t fd = AN_FILE_DESCR_INVALID;
    uint8_t *file = AN_REGISTRAR_QUARANTINE_DEVICE_FLENAME;

    /* Delete the old file */
    an_file_delete(file);

    fd = an_file_open(file, AN_FOF_WRITE_ONLY);
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
    an_file_close(fd);
    an_file_copy_to_standby(file);
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

        printf("\n%%ANRA failed to open whitelist file %s, ANRA not unshut", 
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
            an_process_may_suspend();
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
                        &whitelist_device->udi.len, "ANR Whitelist Dev UDI");
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
    uint8_t *file = AN_REGISTRAR_ACCEPTED_DEVICE_FLENAME;
    uint16_t device_suffix = 0;
    an_file_api_ret_enum retval;

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
            an_process_may_suspend();
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
                "ANR Read Acc Dev UDI");
        an_str_alloc_and_copy_buffer(&device_id, &accepted_device->device_id, 
                NULL, "ANR Read Acc Dev Dev");

        accepted_device->device_suffix = device_suffix;

        accepted_device->addr = an_get_v6addr_from_names(anra_info.domain_id, 
                                                 accepted_device->device_id);
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
    uint8_t *file = AN_REGISTRAR_QUARANTINE_DEVICE_FLENAME;
    an_file_api_ret_enum retval;

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
            an_process_may_suspend();
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
                           "ANR Quar Dev UDI");

        if (!an_anra_quarantine_device_db_insert(quarantine_device)) {
            an_anra_quarantine_device_free(quarantine_device);
        }
    } 

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, "\n%sRead quarantine db "
                 "from file %s", an_ra_db, file);
    an_file_close(fd);
    return (TRUE);
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
                 "\n%sInitialized AN Registrar device ID pool", an_ra_db);
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

    if (!device_id) {
        return (0);
    }

    /* Device-id should starts with device_id_prefix */
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

    DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, "\n%ssuffix is %d", 
                 an_ra_db, suffix);

    return (suffix);
}

static uint8_t *
an_anra_add_assign_member_device_id (an_udi_t udi)
{
    uint32_t device_suffix = 0;
    uint8_t suffix_len = 0, device_id_len = 0;
    uint8_t *device_id = NULL;
    an_accepted_device_t *member = NULL;
    uint8_t *my_domain_id = NULL;

    if (!udi.data) {
        return (NULL);
    }    

    member = an_accepted_device_db_search(udi);

    if(member)  {
        DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                     "\n%sFound accepted device [%s] of device_id [%s]", 
                     an_ra_db, udi.data, 
                     member->device_id);
        return member->device_id;
    } 
    
    member = an_accepted_device_alloc();
    member->udi.data = (uint8_t *)an_malloc_guard(udi.len, 
                                    "AN RA Accepted Device UDI");
    if (!member->udi.data) {
        an_accepted_device_free(member);
        return (NULL);
    }
    an_memcpy_guard(member->udi.data, udi.data, udi.len);
    member->udi.len = udi.len;

    device_suffix = an_anra_allocate_device_suffix(0);
    suffix_len = 5;
    device_id_len = suffix_len + an_strlen(anra_info.device_id_prefix) + 1;
    device_id = (uint8_t *)an_malloc_guard(device_id_len, 
                                    "AN RA Accepted Device ID");
    if (!device_id) {
        an_accepted_device_free(member);
        return (NULL);
    }
    an_snprintf(device_id, device_id_len, "%s%d", 
                        anra_info.device_id_prefix, device_suffix);

    member->device_suffix = device_suffix;
    member->device_id = device_id;

    member->addr = an_get_v6addr_from_names(anra_info.domain_id, device_id);
    member->router_id = an_get_v4addr_from_names(anra_info.domain_id, 
                                                 device_id);
    if (!an_accepted_device_db_insert(member)) {
        an_accepted_device_free(member);
    }
    my_domain_id = an_get_domain_id();

    an_syslog(AN_SYSLOG_DEVICE_ALLOWED,
              member->udi.data, my_domain_id, 
              an_addr_get_string(&member->addr),
              member->device_id);

//    an_anra_write_device_suffix_pool_current_index_to_file();
    an_anra_write_accepted_device_to_file(member);

    return (device_id);
}

void
an_anra_set_local_anra_ip (void)
{
    an_addr_t registrar_ip = AN_ADDR_ZERO;

    registrar_ip  = an_get_v6addr_from_names(anra_info.domain_id, 
                                             anra_info.device_id);

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
        anra_info.device_id = (uint8_t *)an_malloc_guard(an_strlen(device_id)+1, 
                                           "ANR device id");
        if (anra_info.device_id) {
            an_memcpy_guard(anra_info.device_id, device_id, 
                            an_strlen(device_id)+1);
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sAN Registrar's device_id is set to %s",
                         an_ra_event, anra_info.device_id);
        } else {
            return (ANR_CONFIG_ERR_NOT_CONFIG);
        }
    }

    return (ANR_CONFIG_ERR_NONE);
}

static boolean
an_anra_bootstrap_thyself (void)
{
    an_udi_t udi = {};

    if (!an_anra_cs_up()) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sWaiting till CS comes up to bootstrap thyself",
                     an_bs_pak);
        an_timer_start(&an_anra_cs_check_timer, AN_ANRA_CS_CHECK_INTERVAL);
        return (TRUE);
    }

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

    if (an_anra_cs_up()) {
        if (!an_tp_exists(AN_DOMAIN_TP_LABEL) ||
            !an_get_device_id() || !an_get_domain_id() ||
            !an_get_domain_cert(&domain_cert)) {

            an_anra_bootstrap_thyself();
            an_syslog(AN_SYSLOG_ANRA_UP, an_get_domain_id(), an_get_device_id());

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

boolean
an_anra_is_device_not_ra_and_bootstrapped (void)
{
    if (an_tp_exists(ANRA_CS_TP_LABEL)) {
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
                     "as AN Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (anra_info.state == ANR_INFO_STATE_NONE) {
        anra_info.state = ANR_INFO_STATE_INIT;
        anra_info.domain_id = NULL; 
        anra_info.device_id_prefix = AN_REGISTRAR_DEVICE_ID_PREFIX; 
        anra_info.whitelist_filename = NULL; 
        anra_info.checkUDI = FALSE;

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

    return (TRUE);
}

anr_config_err_e
an_anra_set_domain_id (uint8_t *domain_id)
{
    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as AN Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (!an_is_active_rp()) {
        if (an_anra_is_live_pen_ca()) {
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                        "\n%sRegistrar is live, can't change the current domain",
                        an_ra_event);
            return (ANR_CONFIG_ERR_LIVE);
        }
    } else if (an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sRegistrar is live, can't change the current domain",
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
            an_memcpy_guard(anra_info.domain_id, domain_id, 
                            an_strlen(domain_id)+1);
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                         "\n%sDomain Id [%s] is set for the Registrar", 
                         an_ra_event, anra_info.domain_id);
        } else {
            return (ANR_CONFIG_ERR_NOT_CONFIG);
        }    
    }
    return (ANR_CONFIG_ERR_NONE);
}

uint8_t *
an_anra_get_domain_id (void)
{
    return (anra_info.domain_id);
}

anr_config_err_e
an_anra_set_whitelist_filename (void *whitelist_filename)
{
    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as AN Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    if (an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sRegistrar is live, can't change the current domain",
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
           an_memcpy_guard(anra_info.whitelist_filename, 
                           whitelist_filename, an_strlen(whitelist_filename)+1);
           DEBUG_AN_LOG(AN_LOG_RA_DB, AN_DEBUG_MODERATE, NULL, 
                        "\n%sRegistrar Whitelist set to %s", an_ra_db,
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

anr_config_err_e
an_anra_set_device_id_prefix (void *device_id_prefix)
{
    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured as"
                     "as AN Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    return (ANR_CONFIG_ERR_UNKNOWN);
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
                     "as AN Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }
    
    if (!an_is_active_rp()) {
        if (!an_anra_is_live_pen_ca()) {
            DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                         "\n%sAN Registrar is already shut", an_ra_event);
            return (ANR_CONFIG_ERR_NOT_LIVE);
        }
    } else if (!an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sAN Registrar is already shut", an_ra_event);
        return (ANR_CONFIG_ERR_NOT_LIVE);
    }    

    if (!an_system_is_configured()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sAN Registrar shut is held till the system is ready",
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
                   "\n%sAN Registrar is shut", an_ra_event);
        return ;
    }
    if (an_anra_is_live()) {
        an_timer_stop(&an_anra_cs_check_timer);
        an_anra_cfg_ca_server(ANR_CA_SERVER_COMMAND_SHUT);
    }

    anra_info.state = ANR_INFO_STATE_SHUT;
    
    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                 "\n%sAN Registrar is shut", an_ra_event);

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
    an_cerrno rc = EOK;

    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as AN Registrar", an_ra_event, an_get_domain_id());
        return (ANR_CONFIG_ERR_DEVICE_IN_DOMAIN);
    }

    anr_config_err_e err;

    if (!an_anra_is_configured()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sAN Registrar is not configured, cannot unshut it", 
                     an_ra_event);
        return (ANR_CONFIG_ERR_NOT_CONFIG);
    }

    if (an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sAN Registrar is already live", an_ra_event); 
        return (ANR_CONFIG_ERR_LIVE);
    }

    if (!an_anra_is_minimum_config_done()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sMinimum config required for AN Registrar is not " 
                     "done, cannot unshut", an_ra_event); 
        return (ANR_CONFIG_ERR_NOT_CONFIG);
    }

    if (!an_system_is_configured()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sAN Registrar unshut is held till the system is ready",
                     an_ra_event);
        anra_info.state = ANR_INFO_STATE_LIVE_PENDING;
        return (ANR_CONFIG_ERR_PENDING);
    }

    if (!an_get_udi(&udi)) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sAN Registrar unshut is held till UDI is available",
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
//            err = an_anra_shut();
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

void
an_anra_live_pending (void)
{
    an_cert_t domain_cert = {};
    an_cerrno rc = EOK;

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
    an_timer_init(&an_anra_cs_check_timer, AN_TIMER_TYPE_ANR_CS_CHECK, NULL, FALSE);


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

        an_anra_bootstrap_thyself();
    } else {
        an_anra_set_device_id(an_get_device_id());
        an_anra_set_local_anra_ip();
    }

}
 
anr_config_err_e
an_anra_delete (void)
{
    anr_config_err_e anr_config_err = ANR_CONFIG_ERR_UNKNOWN;

    if (!an_anra_is_configured()) {
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL, 
                     "\n%sAN Registrar is not configured, cannot delete it", 
                     an_ra_event);
        return (ANR_CONFIG_ERR_NONE);
    }

    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as AN Registrar", an_ra_event, an_get_domain_id());
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
    an_anra_set_device_id(NULL);
    an_anra_set_device_id_prefix(NULL);
    an_anra_set_whitelist_filename(NULL);
    if (an_is_active_rp()) {
        an_anra_set_local_anra_ip();
        an_anra_cfg_ca_server(ANR_CA_SERVER_COMMAND_DELETE);
    }
    an_anra_init();

    anra_info.state = ANR_INFO_STATE_NONE;

    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                  "\n%sAN Registrar is deleted", an_ra_event);
    an_event_registrar_uninit();

    an_avl_uninit(&an_accepted_device_tree);
    an_avl_uninit(&an_anra_color_device_tree);
    an_avl_uninit(&an_anra_quarantine_device_tree);

}

/*************************** End of ANRA Configuration Section **************/

void
an_anra_init (void)
{
    an_accepted_device_db_init();
    an_anra_color_device_db_init(0); 
    an_anra_quarantine_device_db_init();

    an_anra_init_device_suffix_pool(0);

    an_file_delete(AN_REGISTRAR_ACCEPTED_DEVICE_FLENAME);
    an_file_delete(AN_REGISTRAR_QUARANTINE_DEVICE_FLENAME);

    
    DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sAN Registrar is initialized", an_ra_event);
}

void
an_anra_uninit (void)
{
    an_anra_init();
}

anr_config_err_e
an_anra_allow_quarantine_device (an_udi_t quarantine_udi)
{
    an_anra_quarantine_device_t *quarantine_device = NULL;
    an_anra_color_device_t *whitelist_device = NULL;

    if (an_anra_is_device_not_ra_and_bootstrapped()) { 
        DEBUG_AN_LOG(AN_LOG_RA_EVENT, AN_DEBUG_MODERATE, NULL,
                     "\n%sDevice is part of %s, it cannot be configured "
                     "as AN Registrar", an_ra_event, an_get_domain_id());
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
        an_memcpy_guard(whitelist_device->udi.data, quarantine_udi.data,
                        quarantine_udi.len);
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

       an_memcpy_guard(quarantine_device->udi.data,
                       message->udi.data,
                       message->udi.len);

       quarantine_device->udi.len = message->udi.len;
       quarantine_device->iptable = message->iptable;
       quarantine_device->anproxy = message->dest;//should be to dst

       if (!an_anra_quarantine_device_db_insert(quarantine_device)) {
           an_anra_quarantine_device_free(quarantine_device);
       }

       an_anra_write_quarantine_device_to_file(quarantine_device);
   }
}

void 
an_anra_udi_available (void)
{
    anr_config_err_e anr_config_err = ANR_CONFIG_ERR_NONE;    

    if (!an_anra_is_configured()) {
        return;
    }
    
    if (!an_system_is_configured()) {
        return;
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
        if (!an_get_device_id() || !an_get_domain_id() || 
            an_memcmp(anra_info.domain_id, an_get_domain_id(), 
                      an_strlen(anra_info.domain_id)+1)) {
            an_anra_bootstrap_thyself();
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
    an_memcpy_guard(message->udi.data, invitee_udi.data, invitee_udi.len);
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
                 "\n%sAN Registrar triggering Nbr Bootstrap Reject message "
                 "to the new quarantined device", an_bs_pak);
    
    if (!invitee_udi.data || !invitee_udi.len) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sInvitee UDI is NULL", an_bs_pak);
        return;
    }

    message = an_msg_mgr_get_empty_message_package();   

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
    an_memcpy_guard(message->udi.data, invitee_udi.data, invitee_udi.len);
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
    an_cert_t ldc = {};
    an_cert_api_ret_enum result;

    if (!invitee_udi.data || !invitee_udi.len) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "%sNull Input Params to send Bootstrap Invite Message", 
                     an_bs_pak);
        return;
    }
    
    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                 "\n%sAN Registrar sending Nbr Bootstrap Invite message", 
                 an_bs_pak);
    message = an_msg_mgr_get_empty_message_package();   

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
        an_msg_mgr_free_message_package(message);
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sBootstrap Invite message has Null udi data", 
                     an_bs_pak);
        return;
    }
    an_memcpy_guard(message->udi.data, invitee_udi.data, invitee_udi.len);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_UDI);

    /* Device ID */
    device_id = an_anra_add_assign_member_device_id(invitee_udi);    
    message->device_id = (uint8_t *)an_malloc_guard(an_strlen(device_id)+1, 
                                                    "AN MSG Device ID");
    if (!message->device_id) {
        an_msg_mgr_free_message_package(message);
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sBootstrap Invite message has Null device Id", 
                     an_bs_pak);
        return;
    }
    an_memcpy_guard(message->device_id, device_id, an_strlen(device_id)+1); 
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DEVICE_ID);

    /* Domain ID */
    domain_id = anra_info.domain_id;
    message->domain_id = (uint8_t *)an_malloc_guard(an_strlen(domain_id)+1, 
                                                    "AN MSG Domain ID");
    if (!message->domain_id) {
        an_msg_mgr_free_message_package(message);
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                  "\n%sBootstap Invite message has Null Domain Id", an_bs_pak);
        return;
    }

    an_memcpy_guard(message->domain_id, domain_id, an_strlen(domain_id)+1);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_DOMAIN_ID);

    /* ANRA IP Addr */
    message->anra_ipaddr = an_anra_get_registrar_ip();
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_ANRA_IPADDR);

    /* ANRA Cert */
    result = an_cert_get_ca_cert_from_tp(ANRA_CS_TP_LABEL, &ldc);
    if (result != AN_CERT_API_SUCCESS) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sWhile triggering Bootstrap Invite Message, %s",
                     an_bs_pak, an_cert_enum_get_string(result));
        return;
    }
    
    DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sObtaining CA Cert from Trustpoint %s", an_bs_pak, 
                     "ANRA_CS_TP_LABEL");
    // crypto_get_ca_cert() use this to get domain ca certificate;
    message->anra_cert.len = ldc.len;
    message->anra_cert.data = (uint8_t *)an_malloc_guard(ldc.len, 
                                                    "AN MSG ANRA Cert");
    if (!message->anra_cert.data) {
        an_msg_mgr_free_message_package(message);
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sBootstrap Invite message has Null Registrar "
                     "Cert Data", an_bs_pak);
        return;
    }
    an_memcpy_guard(message->anra_cert.data, ldc.data, ldc.len);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_ANRA_CERT);

    /* ANRA Signature */
    an_msg_mgr_add_anra_signature(message);
    AN_SET_BIT_FLAGS(message->interest, AN_MSG_INT_ANRA_SIGN);

    an_msg_mgr_send_message(message);
}

void
an_anra_trigger_bs_response_message(an_msg_package *bs_request, an_cert_t *cert)
{
    /* use the same request data structure for response */
    an_msg_package *bs_response = bs_request;
    an_addr_t src = AN_ADDR_ZERO, dest = AN_ADDR_ZERO;

    if (!bs_request || !cert || !cert->data) {
        return;
    }

    /* Free un-necessary request feilds */
    if (bs_request->cert_request.data) {
        an_free_guard(bs_request->cert_request.data);
        bs_request->cert_request.len = 0;
        bs_request->cert_request.data = NULL;
        AN_CLEAR_BIT_FLAGS(bs_request->interest, AN_MSG_INT_CERT_REQ);
    }
    if (bs_request->cert_req_sign.data) {
        an_free_guard(bs_request->cert_req_sign.data);
        bs_request->cert_req_sign.len = 0;
        bs_request->cert_req_sign.data = NULL;
        AN_CLEAR_BIT_FLAGS(bs_request->interest, AN_MSG_INT_CERT_REQ_SIGN);
    }
    if (bs_request->public_key.data) {
        an_free_guard(bs_request->public_key.data);
        bs_request->public_key.len = 0;
        bs_request->public_key.data = NULL;
        AN_CLEAR_BIT_FLAGS(bs_request->interest, AN_MSG_INT_PUB_KEY);
    }

    an_msg_mgr_init_header(bs_response, AN_PROTO_ACP, 
                           AN_MSG_BS_RESPONSE);

    bs_response->domain_cert.len = cert->len;
    bs_response->domain_cert.data = (uint8_t *)an_malloc_guard(
                        bs_response->domain_cert.len, "AN MSG Domain Cert");
    if (!bs_response->domain_cert.data) {
        an_msg_mgr_free_message_package(bs_response);
        return;
    } 
    
    an_memcpy_guard(bs_response->domain_cert.data, cert->data, cert->len);
    AN_SET_BIT_FLAGS(bs_response->interest, AN_MSG_INT_DOMAIN_CERT);
    an_free_guard(cert->data);

    src = bs_request->dest;
    dest = bs_request->src;

    bs_response->src = src;
    bs_response->dest = dest;
    bs_response->iptable = bs_request->iptable;
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
                 "\n%sAN Registrar recieved Nbr Connect Message", an_bs_pak);
    
    if (!an_get_udi(&my_udi)) {
        return;
    }

    my_domain_id = an_get_domain_id();

    if (!message) {
        return;
    }

    if ((message->header.msg_type != AN_MSG_NBR_CONNECT) &&
        (message->header.msg_type != AN_MSG_NBR_RECONNECT)) {
        return;
    }

    if (!message->udi.data || !message->udi.len) {
        return;
    }

    if (!an_anra_is_live()) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                     "\n%sRecieved Nbr Connect, but i'm not the Registrar, "
                     "Ignoring it", an_bs_pak);
        return;
    }

    /* Validate device sUDI, if it is there*/
    if (message->sudi.data && message->sudi.len) {
        DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sDevice %s has Sudi, Validating it",
                     an_bs_pak, message->udi.data);

        if (!an_cert_validate(&message->sudi)) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                         "\n%sDevice Sudi is Invalid, Ignore the device", 
                         an_bs_pak);
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
            } else if(whitelist_device->label == 
                                AN_QUARANTINE_TO_WHITELIST_DEVICE) {
                an_anra_trigger_bs_invite_message(message->udi, 
                                 message->src, an_get_iptable(), NULL);     
 
                an_msg_mgr_free_message_package(message);
                return; 
            }
        } else {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                         "\nUdi [%s] not found in the Whitelist, "
                         "AN Registrar triggers Boostrap Reject Message to it", 
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
an_anra_incoming_bs_request_message (an_msg_package *message)
{
    an_cert_t cert = {};
    an_accepted_device_t *anra_member = NULL;
    an_cert_api_ret_enum result;

    if (!message || !message->udi.data || !message->udi.len) {
        return;
    }

    if (an_anra_is_live()) {

        anra_member = an_accepted_device_db_search(message->udi);
        if (anra_member) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                         "\n%sValidating Udi [%s], AN Registrar now triggering "
                         "device Cert Enrollment", an_bs_pak, message->udi.data);
            result = an_cert_enroll(&message->cert_request, 
                                    message->cert_req_sign, 
                                    &message->public_key, &cert);
            if (result == AN_CERT_MEM_ALLOC_FAIL) {
                 DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                              "\n%sIn device cert Enrollment, %s", an_bs_pak, 
                              an_cert_enum_get_string(result));
                 return;
            }
            an_anra_trigger_bs_response_message(message, &cert);
        } else {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL, 
                     "\n%sUdi[%s] not found in the Accepted Device DB, "   
                     "hence AN Registrar not triggering device cert Enrollment",
                     an_bs_pak, message->udi.data);  
        }
    } else {
        if (!an_bs_forward_message_to_anra(message)) {
            DEBUG_AN_LOG(AN_LOG_BS_PACKET, AN_DEBUG_MODERATE, NULL,
                         "\n%sI'm not AN Registrar and not able to forward "
                         "the Message[%s] to AN Registrar", an_bs_pak, 
                         an_get_msg_name(message->header.msg_type));
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
