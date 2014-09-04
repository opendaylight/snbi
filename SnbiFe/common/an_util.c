/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "../al/an_types.h"
#include "an.h"
#include "an_acp.h"
#include "an_event_mgr.h"
#include "an_if_mgr.h"
#include "an_idp.h"
#include "an_srvc.h"
#include "../al/an_mem.h"
#include "../al/an_pak.h"
#include "../al/an_routing.h"
#include "../al/an_str.h"
#include "../al/an_mem_guard.h"
#include "../al/an_timer.h"
#include "../al/an_tunnel.h"
#include "../al/an_syslog.h"
#include "../al/an_cert.h"
#include "../al/an_file.h"
#include "../al/an_sudi.h"
#include "../al/an_logger.h"
#include "../al/an_addr.h"
#include "../al/an_ipv6.h"
#include "../al/an_if.h"
#include "../al/an_ipsec.h"
#include "../al/an_ike.h"

static boolean an_addr_generator_initialized = FALSE;
an_avl_tree an_mem_elem_tree;
static an_mem_elem_t *an_mem_elem_database = NULL;
char *discriminator = "an_disc";
int  sev_includes_drops_flag = 1;
int  fac_includes_drops_flag = 1;
char *facility_name = "AN";
boolean an_syslog_server_set = FALSE;

const uint8_t * an_cert_debug_enum_string [] = {
    "AN cert API success",
    "memory allocation failed",
    "failed to start PKI session",
    "failed to get cert attribute",
    "failed to sign the message using private key",
    "succesfully enrolled the domain device certificate",
    "domain device certificate enrollment is NBcomplete",
    "Error in domain device certificate enrollment",
    "domain device certificate enrollment granted successfully",
    "failed to set trustpoint enroll",
    "failed to generate domain device certificate signing request",
    "failed to import domain CA certificate",
    "failed to import domain device certificate",
    "AN local CA doesn't exist",
    "failed to remove the domain CA certificate trustpoint",
    "invalid crypto pki session handle",
    "failed to get trust point from label",
    "invalid input params",
    "AN cert enum max",
};
 
const uint8_t *an_cert_enum_get_string (an_cert_api_ret_enum enum_type)
{
    return (an_cert_debug_enum_string[enum_type]);
}

int32_t an_cert_compare (const an_cert_t cert1, const an_cert_t cert2)
{
    if (cert1.len != cert2.len) {
        return (cert1.len - cert2.len);
    }

    if (!cert1.data && !cert2.data) {
        return (0);
    } else if (!cert1.data) {
        return (-1);
    } else if (!cert2.data) {
        return (1);
    }

    return (an_memcmp(cert1.data, cert2.data, cert1.len));
}

boolean an_cert_equal (const an_cert_t cert1, const an_cert_t cert2)
{
    return (!an_cert_compare(cert1, cert2));
}

void an_cert_short_display (const an_cert_t cert, const an_log_type log_type)
{
    uint8_t *subject = NULL;
    uint16_t len = 0;

    if (!cert.data || !cert.len) {
        return;
    }

    if (log_type) {
        an_cert_get_subject_name(cert, &subject, &len);
        an_free_guard(subject);
        subject = NULL;
    }
}

void an_certificate_display (const an_cert_t cert, const an_log_type_e log_type)
{
    uint8_t *subject = NULL;
    uint16_t len = 0;

    if (!cert.data || !cert.len) {
        return;
    }

    if (log_type) {
        an_cert_get_subject_name(cert, &subject, &len);
        DEBUG_AN_LOG(log_type, AN_DEBUG_MODERATE, NULL,
                     "Subject Name %s\n", subject);
        an_free_guard(subject);
        subject = NULL;
    }
}


void an_cert_short_print (const an_cert_t cert)
{
    uint8_t *subject = NULL;
    uint16_t len = 0;

    if (!cert.data || !cert.len) {
        return;
    }

    an_cert_get_subject_name(cert, &subject, &len);
    printf("(sub:) %s", subject);
    an_free_guard(subject);
    subject = NULL;
}

boolean
an_cert_get_udi (const an_cert_t cert, an_udi_t *udi)
{
    uint8_t *subject = NULL, *udi_prefix = "serialNumber=", *tem_str = NULL,
            *udi_in_subject = NULL;
    uint16_t len = 0;

    if (an_cert_get_subject_cn(cert, &subject, &len)
                                != AN_CERT_API_SUCCESS) {
        return (FALSE);
    }
    if (!subject) {
        return (FALSE);
    }

    if (len < an_strlen(udi_prefix)) {
        udi->len = 0;
        udi->data = NULL;
        if (subject) {
            an_free_guard(subject);
            subject = NULL;
        }
        return (FALSE);
    }

    if (!tem_str) {
        udi->len = 0;
        udi->data = NULL;
        if (subject) {
            an_free_guard(subject);
            subject = NULL;
        }
        return (FALSE);
    }

    tem_str = an_strstr(subject, udi_prefix);
    udi_in_subject = tem_str + an_strlen(udi_prefix);
    udi->data = an_malloc_guard(an_strlen(udi_in_subject)+1, "AN Udi In Subject");
    if (!udi->data) {
        if (subject) {
            an_free_guard(subject);
            subject = NULL;
        }
        return (FALSE);
    }
    an_memcpy_guard(udi->data, udi_in_subject, an_strlen(udi_in_subject)+1);
    udi->len = an_udi_trim_and_get_len(udi->data);
    if (subject) {
        an_free_guard(subject);
        subject = NULL;
    }

    return (TRUE);
}

void
an_handle_interface_up (an_if_t ifhndl)
{
    an_event_interface_up(ifhndl);
}

void
an_handle_interface_down (an_if_t ifhndl)
{
    an_event_interface_down(ifhndl);
}

void
an_handle_interface_erased (an_if_t ifhndl)
{
    an_event_interface_erased(ifhndl);
}

void
an_handle_registrar_up(void)
{
    an_event_registrar_up();
}

void
an_handle_registrar_shut(void)
{
    an_event_registrar_shut();
}

void
an_handle_no_registrar(void)
{
    an_event_no_registrar();
}


char*
an_ikev2_get_profile_name (void)
{
    return an_ikev2_profile_name;
}

void
an_ikev2_define_profile_names (uint32_t unit)
{
    if (unit) {
        an_snprintf(an_ikev2_proposal_name, AN_IKEV2_PROPOSAL_NAME_BUF_SIZE,
                 "%s_%d", AN_IKEV2_PROPOSAL_NAME, unit);
        an_snprintf(an_ikev2_policy_name, AN_IKEV2_POLICY_NAME_BUF_SIZE,
                 "%s_%d", AN_IKEV2_POLICY_NAME, unit);
        an_snprintf(an_ikev2_key_name, AN_IKEV2_KEY_NAME_BUF_SIZE,
                 "%s_%d", AN_IKEV2_KEY_NAME, unit);
        an_snprintf(an_ikev2_profile_name, AN_IKEV2_PROFILE_NAME_BUF_SIZE,
                 "%s_%d", AN_IKEV2_PROFILE_NAME, unit);
    }else {
        an_snprintf(an_ikev2_proposal_name, AN_IKEV2_PROPOSAL_NAME_BUF_SIZE,
                 "%s", AN_IKEV2_PROPOSAL_NAME);
        an_snprintf(an_ikev2_policy_name, AN_IKEV2_POLICY_NAME_BUF_SIZE,
                 "%s", AN_IKEV2_POLICY_NAME);
        an_snprintf(an_ikev2_key_name, AN_IKEV2_KEY_NAME_BUF_SIZE,
                 "%s", AN_IKEV2_KEY_NAME);
        an_snprintf(an_ikev2_profile_name, AN_IKEV2_PROFILE_NAME_BUF_SIZE,
                 "%s", AN_IKEV2_PROFILE_NAME);
    }
}

void
an_ikev2_clear_profile_names (void)
{
    uint8_t *null_char = "\0";
    an_snprintf(an_ikev2_proposal_name, AN_IKEV2_PROPOSAL_NAME_BUF_SIZE,
            "%s", null_char);
    an_snprintf(an_ikev2_policy_name, AN_IKEV2_POLICY_NAME_BUF_SIZE,
            "%s", null_char);
    an_snprintf(an_ikev2_key_name, AN_IKEV2_KEY_NAME_BUF_SIZE,
            "%s", null_char);
    an_snprintf(an_ikev2_profile_name, AN_IKEV2_PROFILE_NAME_BUF_SIZE,
            "%s", null_char);
}

const uint8_t *an_file_debug_enum_string [] = {
    "AN file api success",
    "invalid input parameters",
    "failed to open the file",
    "invalid file size",
    "invalid file descriptor",
    "memory allocation failed",
    "file size not equal to data size",
    "failed to write to the file",
    "read more than the file max size",
    "failed to read from file",
    "filename doesn't exist",
    "AN file enum max",
};

const uint8_t *an_file_enum_get_string (an_file_api_ret_enum enum_type)
{
    return (an_file_debug_enum_string[enum_type]);
}

boolean
an_file_descr_is_valid (an_file_descr_t fd)
{
    return (fd != AN_FILE_DESCR_INVALID);
}

an_file_api_ret_enum
an_file_read_next_word (an_file_descr_t fd, an_buffer_t *word, uint32_t max_len)
{
    uint8_t str[AN_FILE_MAX_READ_SIZE] = {};
    uint32_t i = 0, j = 0, len = 0;
    int8_t ch = '0';
    boolean word_found = FALSE, word_end = FALSE;
    an_file_api_ret_enum retval = AN_FILE_OPEN_FAIL;

    if (!an_file_descr_is_valid(fd)) {
        return (AN_FILE_INVALID_DESCR);
    }

    /* As of now, there is no use-case to read more than AN_FILE_MAX_READ_SIZE
     * bytes in single read, increase AN_FILE_MAX_READ_SIZE in future if required */ 
    if (max_len > AN_FILE_MAX_READ_SIZE) {
        return (AN_FILE_READ_MAX);
    }

    for (i = 0, j = 0; i < max_len; i++) {
        retval = an_file_read_next_char(fd, &ch);
        if (retval != AN_FILE_API_SUCCESS) {
            return (retval);
        }

        /* Ignores leading spaces, reads word and moves the cursor
         * till the start of the next word. Line boundary would
         * never be crossed */

        if ((ch != ' ') && (ch != '\n') && (ch != -1)) {
            if (!word_end) {
                word_found = TRUE;
                str[j++] = ch;
            } else if (word_end) {
                an_file_seek(fd, -1, AN_FILE_SEEK_CUR);
                break;
            }

        } else if (ch == ' ') {
            if (word_found) {
                str[j++] = '\0';
                word_end = TRUE;
            }

        } else if ((ch == '\n') || (ch == -1)) {
            break;
        }
    }

    if (i == max_len) {
        return (AN_FILE_READ_MAX);
    }

    len = an_udi_trim_and_get_len(str);
    if (!len) {
        return (AN_FILE_INPUT_PARAM_INVALID);
    }

    an_str_get_temp_buffer(word);
    word->len = len;
    an_memcpy(word->data, str, word->len);

    return (AN_FILE_API_SUCCESS);
}

an_file_api_ret_enum
an_file_read_next_udi (an_file_descr_t fd, an_udi_t *udi, uint32_t max_len)
{
    an_buffer_t pid = {}, sn = {}, buffer = {};
    an_file_api_ret_enum retval = AN_FILE_OPEN_FAIL;

    if (!an_file_descr_is_valid(fd)) {
        return (AN_FILE_INVALID_DESCR);
    }

    /* As of now, there is no use-case to read more than AN_FILE_MAX_READ_SIZE
     * bytes in single read, increase AN_FILE_MAX_READ_SIZE in future if required */ 
    if (max_len > AN_FILE_MAX_READ_SIZE) {
        return (AN_FILE_READ_MAX);
    }

    /* Read PID: portion of UDI */
    retval = an_file_read_next_word(fd, &buffer, max_len/2);
    if (retval != AN_FILE_API_SUCCESS) {
        return (retval);
    }
    an_str_get_temp_buffer(&pid);
    an_memcpy(pid.data, buffer.data, buffer.len);
    pid.len = buffer.len;

    /* Read SN: portion of UDI */
    retval = an_file_read_next_word(fd, &buffer, max_len/2);
    if (retval != AN_FILE_API_SUCCESS) {
        return (retval);
    }
    an_str_get_temp_buffer(&sn);
    an_memcpy(sn.data, buffer.data, buffer.len);
    sn.len = buffer.len;

    an_str_get_temp_buffer(&buffer);
    udi->data = buffer.data;
    udi->len = (pid.len - 1) + 1 + (sn.len - 1) + 1;

    an_memcpy(udi->data, pid.data, pid.len - 1);
    udi->data[pid.len - 1] = ' ';

    an_memcpy(udi->data + pid.len, sn.data, sn.len - 1);
    udi->data[pid.len + sn.len - 1] = '\0';

    return (retval);
}

an_file_api_ret_enum
an_file_read_next_line (an_file_descr_t fd, an_buffer_t *line, uint32_t max_len)
{
    uint8_t str[AN_FILE_MAX_READ_SIZE] = {};
    uint32_t i = 0, len = 0;
    int8_t ch = '0';

    if (!an_file_descr_is_valid(fd)) {
        return (AN_FILE_INVALID_DESCR);
    }

    /* As of now, there is no use-case to read more than AN_FILE_MAX_READ_SIZE
     * bytes in single read, increase AN_FILE_MAX_READ_SIZE in future if required */ 
    if (max_len > AN_FILE_MAX_READ_SIZE) {
        return (AN_FILE_READ_MAX);
    }

    for (i = 0; i < max_len; i++) {
        if (an_file_read_next_char(fd, &ch) != AN_FILE_READ_CHAR_FAIL) {
            if ((ch == '\n') || (ch == -1)) {
                str[i] = '\0';
                break;
            } else {
                str[i] = ch;
            }
        } else {
          return(AN_FILE_READ_CHAR_FAIL);
        }
    }
    if (i == max_len) {
        return (AN_FILE_READ_MAX);
    }

    len = an_udi_trim_and_get_len(str);
    if (!len) {
        return (AN_FILE_INPUT_PARAM_INVALID);
    }

    an_str_get_temp_buffer(line);
    line->len = len;
    an_memcpy(line->data, str, line->len);

    return (AN_FILE_API_SUCCESS);
}

boolean
an_file_read_next_byte (an_file_descr_t fd, uint8_t *byte)
{
    return (an_file_read_next_char(fd, (int8_t *)byte));
}

an_file_api_ret_enum
an_file_write_byte (an_file_descr_t fd, uint8_t *byte)
{
    return (an_file_write_char(fd, (int8_t *)byte));
}

an_file_api_ret_enum
an_file_write_line_terminator (an_file_descr_t fd)
{
    return (an_file_write_char(fd, "\n"));
}

void
an_ipsec_set_profile_name (uint32_t unit)
{
    if (unit) {
        an_snprintf(an_ipsec_profile_name, AN_IPSEC_PROFILE_NAME_BUF_SIZE,
                 "%s_%u", AN_IPSEC_PROFILE_NAME, unit);
    } else {
        an_snprintf(an_ipsec_profile_name, AN_IPSEC_PROFILE_NAME_BUF_SIZE,
                 "%s", AN_IPSEC_PROFILE_NAME);
    }
    DEBUG_AN_LOG(AN_LOG_BS_EVENT, AN_DEBUG_MODERATE, NULL,
     "\n%sChoosing IPSec Profile name %s", an_bs_event, an_ipsec_profile_name);
}

void
an_ipsec_clear_profile_name (void)
{
    an_ipsec_profile_id = AN_IPSEC_PROFILE_NUM_START;
    an_ipsec_set_profile_name(an_ipsec_profile_id);
   // uint8_t *null_char = "\0";
   // snprintf(an_ipsec_profile_name, AN_IPSEC_PROFILE_NAME_BUF_SIZE,
   //         "%s", null_char);

}

boolean an_ipv6_preroute_and_forward_pak (an_pak_t *pak, an_if_t ifhndl,
                                          an_addr_t nhop)
{
    an_log(AN_LOG_PAK, "\n%sPrerouting packet %x on interface %s to nhop %s",
            an_pak_prefix, pak, an_if_get_name(ifhndl),
            an_addr_get_string(&nhop));
    an_ipv6_preroute_pak(pak, ifhndl, nhop);
    an_ipv6_forward_pak(pak);

    return (TRUE);
}

/*
 * an_ipv6_unicast_routing_enable_disable_cb
 */
void
an_ipv6_unicast_routing_enable_disable_cb (boolean sense)
{
    an_routing_cfg_t routing_info = {};
    an_cert_t domain_cert = {};
    boolean is_autonomic_ok = FALSE;

    an_get_domain_cert(&domain_cert);
    if (!an_is_global_cfg_autonomic_enabled() && !an_acp_is_initialized()
        && (!domain_cert.len || !domain_cert.data)) {
        is_autonomic_ok = FALSE;
    }
    else {
        is_autonomic_ok = TRUE;
    }

    if(sense) {
        /* ipv6 unicast-routing is enabled */
        an_ipv6_unicast_routing_enabled = TRUE;
        if (is_autonomic_ok) {
            routing_info = an_get_routing_info();
            an_rpl_global_enable(&routing_info.an_rpl_info);
            an_acp_routing_enable_on_required_interfaces(&routing_info);
        }
    }
    else {
        /* ipv6 unicast-routing is disabled */
        an_ipv6_unicast_routing_enabled = FALSE;
        if (is_autonomic_ok) {
            printf("\n Warning: autonomic-networking will not work, please enable 'ipv6 unicast-routing'"); 
        }
    }
}

#if 0
static ipv6_nd_feat_rc_t
an_ipv6_nd_process_in_feature (uint32_t ifhndl, struct paktype_ *pak,
                               struct ip6_hdr *ipv6_hdr, struct icmp6_hdr *icmp6_hdr) 
{
    an_msg_mgr_incoming_ipv6_na(pak, ifhndl, ipv6_hdr, icmp6_hdr);
    return (IPV6_ND_FEAT_RC_OK);
}

static ipv6_nd_feat_rc_t
an_ipv6_nd_process_out_feature (uint32_t ifhndl, struct paktype_ **pak,
                                uint32_t *bufsize, struct ip6_hdr *ipv6_hdr,
                                struct icmp6_hdr *icmp6_hdr)
{
    an_msg_mgr_outgoing_ipv6_na(*pak, ifhndl, ipv6_hdr, icmp6_hdr);
    return (IPV6_ND_FEAT_RC_OK);
}
#endif

an_avl_compare_e
an_mem_elem_compare (an_avl_node_t *node1, an_avl_node_t *node2)
{
    an_mem_elem_t *mem_elem = (an_mem_elem_t *)node1;
    an_mem_elem_t *goal_mem_elem = (an_mem_elem_t *)node2;

    if (!mem_elem && !goal_mem_elem) {
        return (AN_AVL_COMPARE_EQ);
    } else if (!mem_elem) {
        return (AN_AVL_COMPARE_LT);
    } else if (!goal_mem_elem) {
        return (AN_AVL_COMPARE_GT);
    }

//    an_log(AN_LOG_MEM, "\n(%u, %d, %s) -> (%u, %d, %s)", 
//           mem_elem->buffer, mem_elem->buffer_size, mem_elem->name,
//           goal_mem_elem->buffer, goal_mem_elem->buffer_size, goal_mem_elem->name); 

    if (goal_mem_elem->buffer < mem_elem->buffer) {
        return (AN_AVL_COMPARE_LT);
    } else if ((uint8_t *)goal_mem_elem->buffer >
               ((uint8_t*)(mem_elem->buffer) + mem_elem->buffer_size)) {
        return (AN_AVL_COMPARE_GT);
    } else {
        return (AN_AVL_COMPARE_EQ);
    }
}

boolean
an_mem_elem_db_insert (an_mem_elem_t *mem_elem)
{
    if (!mem_elem) {
        return (FALSE);
    }

    an_log(AN_LOG_MEM, "\nInserting MEM ELEM (%u, %d) into MEM ELEM DB",
           mem_elem->buffer, mem_elem->buffer_size);
    an_avl_insert_node((an_avl_top_p *)&an_mem_elem_database,
                                       (an_avl_node_t *)mem_elem, 
                                       an_mem_elem_compare,
                                       &an_mem_elem_tree);  

    return (TRUE);
}

boolean
an_mem_elem_db_remove (an_mem_elem_t *mem_elem)
{
    if (!mem_elem) {
        return (FALSE);
    }

    an_log(AN_LOG_MEM, "\nRemoving MEM ELEM (%u, %d) from MEM ELEM DB",
           mem_elem->buffer, mem_elem->buffer_size);
    an_avl_remove_node((an_avl_top_p *)&an_mem_elem_database,
                  (an_avl_node_t *)mem_elem, an_mem_elem_compare, 
                  &an_mem_elem_tree);

    return (TRUE);
}

an_mem_elem_t *
an_mem_elem_db_search (void *buffer)
{
    an_mem_elem_t goal_mem_elem = {};
    an_mem_elem_t *mem_elem = NULL;

    an_avl_node_t *avl_type  = (an_avl_node_t *)&goal_mem_elem;
    an_log(AN_LOG_MEM, "\nSearching MEM ELEM (%u, %d) in MEM ELEM DB",
           buffer, 0);

    goal_mem_elem.buffer = (uint8_t *)buffer;
    goal_mem_elem.buffer_size = 0;

    mem_elem = (an_mem_elem_t *)
          an_avl_search_node((an_avl_top_p)an_mem_elem_database,
                             avl_type, an_mem_elem_compare,
                             &an_mem_elem_tree);

    return (mem_elem);
}

void
an_mem_elem_db_walk (an_avl_walk_f walk_func, void *args)
{
    an_log(AN_LOG_MEM, "\nWalking MEM ELEM DB");
    an_avl_walk_all_nodes((an_avl_top_p *)&an_mem_elem_database, walk_func,
                          an_mem_elem_compare, args, &an_mem_elem_tree);
}

an_walk_e
an_mem_elem_db_init_cb (an_avl_node_t *node, void *args)
{
    an_mem_elem_t *mem_elem = (an_mem_elem_t *)node;

    if (!mem_elem) {
        return (AN_WALK_FAIL);
    }

    an_mem_elem_free(mem_elem);

    return (AN_WALK_SUCCESS);
}

void
an_mem_elem_db_init (void)
{
    an_log(AN_LOG_MEM, "\nInitializeing MEM ELEM DB");
    an_mem_elem_db_walk(an_mem_elem_db_init_cb, NULL);
}

an_walk_e
an_mem_show_cb (an_avl_node_t *node, void *args)
{
    an_mem_elem_t *elem = (an_mem_elem_t *)node;

    if (!elem) {
        return (AN_WALK_FAIL);
    }

    printf("\n%50s %10u %10d", elem->name, elem->buffer, elem->buffer_size);

    return (AN_WALK_SUCCESS);
}

void
an_mem_show (void)
{
    an_mem_elem_db_walk(an_mem_show_cb, NULL);
}

void
an_mem_guard (void *target, uint16_t length)
{
    an_mem_elem_t *elem = NULL;

    elem = an_mem_elem_db_search(target);

    if (!elem) {
        an_log(AN_LOG_MEM, "\nMem-Gaurd: Accessing unallocated memory"
               " target (%u, %d)", target, length);
        //bugtrace();

    } else if (((uint8_t *)target + length) >
               ((uint8_t *)(elem->buffer) + elem->buffer_size)) {
        an_log(AN_LOG_MEM, "\nMem-Gaurd: Overrunning the allocated block"
               "block = (%u, %d), target = (%u, %d)",
               elem->buffer, elem->buffer_size, target, length);
        //bugtrace();
    }
}

void
an_mem_guard_add (void *buffer, uint32_t size, uint8_t *name)
{
    an_mem_elem_t *elem = NULL, *elem_found = NULL;

    if (!buffer || !size) {
        return;
    }

    elem = an_mem_elem_alloc();
    if (!elem) {
        an_log(AN_LOG_MEM, "\nFailed to alloc mem elem");
        return;
    }

    an_strncpy_s(elem->name, 50, name, 49);
    elem->name[49] = '\0';
    elem->buffer = (uint8_t *)buffer;
    elem->buffer_size = size;

    elem_found = an_mem_elem_db_search(elem->buffer);

    if (elem_found) {
        an_log(AN_LOG_MEM, "\nBuffer (%u, %d, %s) already found while searching for (%u, %d, %s)",  
               elem_found->buffer, elem_found->buffer_size, elem_found->name,
               elem->buffer, elem->buffer_size, elem->name);
        return;
    }

    an_mem_elem_db_insert(elem);
}

void
an_mem_guard_remove (void *buffer)
{
    an_mem_elem_t *elem = NULL;

    elem = an_mem_elem_db_search(buffer);
    if (!elem) {
        an_log(AN_LOG_MEM, "\nIt is likely that the memory %u to be released "
               "was not allocated", buffer);
        //bugtrace();
        return;
    }

    an_mem_elem_db_remove(elem);
    an_mem_elem_free(elem);
}

uint64_t
an_pow (uint32_t num, uint32_t pow)
{
    uint32_t i = 1;
    uint64_t res = 1;

    for (i = 1; i <= pow; i++) {
        res *= num;
    }

    return (res);
}

void
an_ntp_clock_sync_from_ntp (void)
{
    an_event_clock_synchronized();
}

an_cerrno an_pak_alloc (uint16_t pak_len, an_pak_t **pak)
{
    an_cerrno rc = EOK;
    rc = an_getbuffer(pak_len, pak);

    if (CERR_IS_NOTOK(rc)) {
        *pak = NULL;
        return (rc);
    }

    an_pak_set_datagram_size(*pak, pak_len);
    an_pak_set_linktype(*pak, AN_LINK_IPV6);

    return(rc);
}

uint16_t
an_udi_trim_and_get_len (uint8_t *string)
{
   uint16_t udilen = 0;

   string = an_strTrim(string);
   if (an_strlen(string) == 0)    {
      return 0;
   }else {
      udilen = an_strlen(string) + AN_UDI_STR_TERMINATOR_LEN;
   }
   return udilen;
}

void
an_sudi_uninit (void)
{
    check_count = 0;
    DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%sUninitializing SUDI", an_nd_event);
    udi_available = FALSE;
    an_sudi_initialized = FALSE;
    an_sudi_available = FALSE;
    an_timer_stop(&an_sudi_check_timer);
}

void
an_sudi_init (void)
{
    if(an_sudi_initialized == FALSE)    {
        an_timer_init(&an_sudi_check_timer, AN_TIMER_TYPE_SUDI_CHECK, NULL, FALSE); 

        an_sudi_initialized = TRUE;
        an_sudi_check();
    }
}

void
an_sudi_clear (void)
{
    an_sudi_uninit();

    an_sudi_init();
}

void
an_syslog_connect (void)
{
   an_if_t syslog_ifhndl = an_get_autonomic_loopback_ifhndl();
   an_idbtype  *an_idb = an_if_number_to_swidb(syslog_ifhndl);


   if (!hstaddran) {
      DEBUG_AN_LOG(AN_LOG_SRVC_SYSLOG, AN_DEBUG_MODERATE, NULL,
            "\n%sSyslog server address is NULL- cant connect", an_nd_event);
          return;
   }

   if (an_addr_is_zero(*hstaddran)) {
      DEBUG_AN_LOG(AN_LOG_SRVC_SYSLOG, AN_DEBUG_MODERATE, NULL,
        "\n%sSyslog server address is UNKNOWN, cant connect", an_nd_event);
      return;
   }

   if (an_syslog_server_set == FALSE) {
      if (discriminator != NULL) {
        an_logger_discriminator(discriminator, fac_includes_drops_flag,
                              facility_name, sev_includes_drops_flag,
                              "1,2,3,4,5,6,7", TRUE);
      }

      an_syslog_config_host(hstaddran,
                         an_idb, discriminator);
      an_syslog_server_set = TRUE;
   }
}

void
an_syslog_disconnect (void)
{
   if (!hstaddran  || !an_acp_is_initialized() || an_addr_is_zero(*hstaddran)) {
      DEBUG_AN_LOG(AN_LOG_SRVC_SYSLOG, AN_DEBUG_MODERATE, NULL,
            "\n%sSyslog server address NULL- cant disconnect", an_srvc_syslog);
          return;
   }
   an_syslog_delete_host(hstaddran);
   *hstaddran = AN_ADDR_ZERO;
   an_syslog_server_set = FALSE;
   if (discriminator != NULL) {
      an_logger_discriminator(discriminator, 0, NULL, 0, NULL, FALSE);
   }
}

void
an_syslog_set_server_address (an_addr_t *syslog_addr, boolean service_add)
{
   if (!hstaddran || !syslog_addr) {
        return;
   }

   if (service_add) {
          *hstaddran = *syslog_addr;
      if (an_acp_is_initialized()) {
         //printf ("\n Add connection AN syslog addr %s , ADD %d", an_addr_get_string(syslog_addr), service_add); 
         an_syslog_connect();
      }
   } else {
       //printf ("\n Remove connection AN syslog addr %s , ADD %d", an_addr_get_string(syslog_addr), service_add); 
       an_syslog_disconnect();
   }
}

void
an_syslog_uninit (void)
{
   an_free(hstaddran);
}

void 
an_process_timer_events (an_timer *expired_timer)
{
    uint32_t timer_type = AN_TIMER_TYPE_NONE;
    void *context = NULL;

    timer_type = an_mgd_timer_type(expired_timer);
    an_log_type_e log;
    log = an_get_log_timer_type(timer_type);
    DEBUG_AN_LOG(log, AN_DEBUG_MODERATE, NULL, "\n%sTimer_Type [%s] Expired", 
                 an_get_log_str(log), an_timer_get_timer_type_str(timer_type)); 

    switch (timer_type) {
        case AN_TIMER_TYPE_SUDI_CHECK:
            an_timer_stop(expired_timer);
            an_sudi_check();
            break;

        case AN_TIMER_TYPE_IF_BRING_UP:
            an_timer_stop(expired_timer);
            an_if_bring_up_all();
            break;

        case AN_TIMER_TYPE_NI_CERT_REQUEST:
            context = an_mgd_timer_context(expired_timer);
            an_timer_stop(expired_timer);
            an_event_ni_cert_request_timer_expired(context);
            break;


        case AN_TIMER_TYPE_PER_NBR_LINK_CLEANUP:
            context = an_mgd_timer_context(expired_timer);
            an_timer_stop(expired_timer);
            an_event_nbr_link_cleanup_timer_expired(context);
            break;

        case AN_TIMER_TYPE_HELLO_REFRESH:
            an_timer_stop(expired_timer);
            an_event_hello_refresh_timer_expired();
            break;
#ifndef AN_IDP_PUSH
        case AN_TIMER_TYPE_IDP_REQUEST:
            an_mgd_timer_context(expired_timer);
            an_timer_stop(expired_timer);
            an_idp_nbr_retransmit_timer_expired();
            break;
             
        case AN_TIMER_TYPE_IDP_REFRESH:
            context = an_mgd_timer_context(expired_timer);
            an_timer_stop(expired_timer);
            an_idp_nbr_ack_timer_expired_v2(context);
            break;
#else
        case AN_TIMER_TYPE_IDP_REFRESH:
            context = an_mgd_timer_context(expired_timer);
            an_timer_stop(expired_timer);
            an_idp_nbr_ack_timer_expired(context);
            break;
#endif
        case AN_TIMER_TYPE_AAA_INFO_SYNC:
            context = an_mgd_timer_context(expired_timer);
            an_timer_stop(expired_timer);
            an_srvc_nbr_ack_timer_expired(context,timer_type);
            break;

        default:
            DEBUG_AN_LOG(log, AN_DEBUG_MODERATE, NULL, "\n%sTimer_Type [%s] invalid", 
                   an_get_log_str(log), an_timer_get_timer_type_str(timer_type)); 
            break;
    }
}

an_log_type_e an_get_log_type (uint8_t protocol_type, uint16_t msg_type)
{
    switch (protocol_type) {
        case AN_PROTO_CHANNEL_DISCOVERY:
            switch (msg_type)  {
                case AN_MSG_UNTRUSTED_L2_CHANNEL_HELLO_REQ:
                case AN_MSG_UNTRUSTED_L2_CHANNEL_HELLO_RESP:
                    return (AN_LOG_ND_PACKET);
                default:
                    break;
            }
            break;
        case AN_PROTO_ADJACENCY_DISCOVERY:
            switch (msg_type) {
                case AN_MSG_ND_HELLO:
                    return (AN_LOG_ND_PACKET);
                default:
                    break;
            }
            break;
        case AN_PROTO_ACP:
            switch (msg_type) {
                case AN_MSG_ND_CERT_REQUEST:
                case AN_MSG_ND_CERT_RESPONSE:
                    return (AN_LOG_ND_PACKET);
                case AN_MSG_BS_INVITE:
                case AN_MSG_BS_REJECT:
                case AN_MSG_BS_REQUEST:
                case AN_MSG_BS_RESPONSE:
                case AN_MSG_BS_ENROLL_QUARANTINE:
                case AN_MSG_ACP_DATA:
                case AN_MSG_NBR_CONNECT:
                case AN_MSG_NBR_RECONNECT:
                case AN_MSG_NBR_JOIN:
                case AN_MSG_NBR_LEAVE:
                case AN_MSG_NBR_LOST:
                case AN_MSG_NBR_MODIFY:
                    return (AN_LOG_BS_PACKET);
                case AN_MSG_IDP_INTENT:
                case AN_MSG_IDP_ACK:
                case AN_MSG_IDP_INTENT_VERSION:
                case AN_MSG_IDP_INTENT_REQUEST:
                case AN_MSG_SERVICE_INFO:
                case AN_MSG_SERVICE_INFO_ACK:
                    return (AN_LOG_SRVC_PACKET);
                default:
                    break;
             }
            break;
        default:
            break;
        }
        return AN_LOG_NONCE;
}

/*
*  This function initializes a table indexed by ascii character code
*  Value at each index corresponds to 6 bit code that will be used
*  to generate SubnetID + InterfaceID part of IPv6 address to be 
*  assigned to loopback interface 
*/
void an_generate_address_codes(void)
{
   uint8_t some_letter = 0;
   an_memset(&an_ipv6_addr_codes[0],0,AN_IPV6_MAX_ADDR_CODES);
   /* Start codes from 1 as 0 will be used for non hostname standard 
      characters */
   uint8_t code = 1;

   /* Assign codes for characters a-z */
   for(some_letter='a';some_letter<='z'; some_letter++)
   {
      an_ipv6_addr_codes[some_letter] = code;
      code++;
   }

   /* Assign codes for characters 0-9 */
   for(some_letter='0';some_letter<='9'; some_letter++)
   {
      an_ipv6_addr_codes[some_letter] = code;
      code++;
   }

   /* Assign codes for characters '-' and '_' */
   an_ipv6_addr_codes['-'] = code;
   code++;
   an_ipv6_addr_codes['_'] = code;
}

static boolean
an_addr_generator_is_initialized (void)
{
    return (an_addr_generator_initialized);
}

void an_addr_generator_init (void)
{
    if (an_addr_generator_is_initialized()) {
        return;
    }

    an_generate_address_codes();

    an_addr_generator_initialized = TRUE;
}

void an_addr_generator_uninit (void)
{
   return;
}

void
an_get_ipv4_router_id_from_device_id (uint8_t *device_id, uint32_t *router_id)
{
    uint8_t i = 0, j = 0, device_id_len = 0;
    uint32_t v4addr = 0;
    uint32_t addr_code = 0;

    if (!router_id) {
        return;
    }

    /* Max 4 charactes can be used to generate RouterID 
       get offset in IPv4 address where generated RouterID 
       will be written */
    if (an_strlen(device_id) > AN_IPV4_MAX_ADDR_CODE_LEN) {
        device_id += (an_strlen(device_id) - AN_IPV4_MAX_ADDR_CODE_LEN);
    }

    device_id_len = an_strlen(device_id);

    for (i = 0, j = 1;
         (i < AN_IPV4_MAX_ADDR_CODE_LEN) && (j <= device_id_len);
         i++, j++) {
        addr_code = an_ipv6_addr_codes[device_id[device_id_len - j]];
        addr_code = addr_code << (6*(j-1));
        v4addr |= addr_code;
    }

    v4addr |= 0x0A000000;

    *router_id = v4addr;
}

inline int32_t an_addr_comp (const an_addr_t *addr1, const an_addr_t *addr2)
{
    return (an_memcmp((void *)addr1, (void *)addr2, sizeof(an_addr_t)));
}

inline boolean an_addr_equal (const an_addr_t *addr1, const an_addr_t *addr2)
{
    return (!an_addr_comp(addr1, addr2));
}

inline boolean an_addr_is_zero (const an_addr_t addr)
{
    return (an_addr_equal(&addr, &AN_ADDR_ZERO));
}

an_addr_t
an_get_v6addr_from_names (uint8_t *domain_id, uint8_t *device_id)
{
    an_addr_t addr = an_site_local_prefix;
    an_v6addr_t v6addr = an_addr_get_v6addr(addr);

    /* set p_router_id_8 to IPv6 ADDR's 2nd byte(GROUPID), 1st is fixed 0xFD
       as in an_nw_prefix */
    uint8_t *p_router_id_8 = ((uint8_t *)&v6addr) + 1;

    if (!domain_id || !device_id) {
        return (AN_ADDR_ZERO);
    }

    an_get_ipv6_group_id_frm_domain(domain_id, p_router_id_8);

    p_router_id_8+=5;

    an_get_ipv6_interface_id_frm_device_id(device_id, p_router_id_8);

    an_addr_set_from_v6addr(&addr, v6addr);
    return (addr);
}

an_v4addr_t
an_get_v4addr_from_names(uint8_t *domain_id, uint8_t *device_id)
{
    uint32_t router_id = AN_RID_PREFIX;

    if (!device_id) {
        return (0);
    }

    an_get_ipv4_router_id_from_device_id(device_id, &router_id);
    return (router_id);
}

