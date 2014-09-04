/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_NBR_DB_H__
#define __AN_NBR_DB_H__

#include "../al/an_types.h"
#include "../al/an_avl.h"
#include "../al/an_cert.h"
#include "../al/an_list.h"
#include "an.h"

typedef enum an_acp_channel_type_e_ {
    AN_ACP_CHANNEL_NONE         = (0),
    AN_ACP_CHANNEL_PHYSICAL     = (1 << 0),
    AN_ACP_CHANNEL_GRE_IPV6     = (1 << 1),
    AN_ACP_CHANNEL_VLAN         = (1 << 2),
} an_acp_channel_type_e;

typedef enum an_acp_sec_type_e_ {
    AN_ACP_SEC_NONE             = (0),
    AN_ACP_SEC_IPSEC            = (1 << 0),
    AN_ACP_SEC_MACSEC           = (1 << 1),
} an_acp_sec_type_e;

typedef enum an_acp_tunn_state_e_ {
    AN_ACP_TUNN_NONE = 0,
    AN_ACP_TUNN_CREATED_UP,
    AN_ACP_TUNN_CREATED_DOWN,
} an_acp_tunn_state_e;

typedef enum an_acp_vlan_state_e_ {
    AN_ACP_VLAN_NONE = 0,
    AN_ACP_VLAN_CREATED_UP,
    AN_ACP_VLAN_CREATED_DOWN,
} an_acp_vlan_state_e;

typedef struct an_acp_phy_info_t_ {
    an_if_t ifhndl;
} an_acp_phy_info_t;

typedef struct an_acp_tunn_info_t_ {
    an_if_t ifhndl;
    an_acp_tunn_state_e state;
} an_acp_tunn_info_t;

typedef struct an_acp_vlan_info_t_ {
    uint16_t number;
    an_acp_vlan_state_e state;
} an_acp_vlan_info_t;

union an_acp_channel_spec_t {
    an_acp_phy_info_t phy_info;
    an_acp_tunn_info_t tunn_info;
    an_acp_vlan_info_t vlan_info;
};

typedef struct an_acp_ipsec_info_t_ {
    uint inbound_ah_spi;
    uint outbound_ah_spi;
    char *inbound_ah_key;
    char *outbound_ah_key;
    uint inbound_esp_spi;
    uint outbound_esp_spi;
    char *inbound_esp_auth_key;
    char *outbound_esp_auth_key;
    char *inbound_esp_cipher_key;
    char *outbound_esp_cipher_key;
    uint transform[2];
    boolean tunnel_mode;
    
    char an_ipsec_policy[31];
}an_acp_ipsec_info_t;

typedef struct an_acp_macsec_info_t_ {
    /*do be done later */
    uint inbound_ah_spi;
    uint outbound_ah_spi;
    char *inbound_ah_key;
    char *outbound_ah_key;
    uint inbound_esp_spi;
    uint outbound_esp_spi;
    char *inbound_esp_auth_key;
    char *outbound_esp_auth_key;
    char *inbound_esp_cipher_key;
    char *outbound_esp_cipher_key;
    uint transform[2];
    boolean tunnel_mode;
    
    char an_ipsec_policy[31];
}an_acp_macsec_info_t;

union an_acp_sec_spec_t {
    /* change this as required once ipsec/macsec is added */
    an_acp_ipsec_info_t ipsec_info;
    an_acp_macsec_info_t macsec_info; 
};

typedef struct an_acp_channel_info_t_ {
    an_acp_channel_type_e channel_negotiated;
    an_acp_channel_type_e channel_type; 
    union an_acp_channel_spec_t channel_spec; 
    an_acp_sec_type_e sec_negotiated;
    an_acp_sec_type_e sec_type; 
    union an_acp_sec_spec_t sec_spec;
} an_acp_channel_info_t;

typedef struct an_intent_file_t_ {
    uint32_t len;
    uint8_t *data;
} an_intent_file_t;

/* change an_idp_hton_version() & an_idp_ntoh_version() 
 * if and when an_intent_ver_t definition is changed */
typedef uint32_t an_intent_ver_t;

typedef struct an_idp_info_t_ {
    an_intent_ver_t version;
    an_intent_file_t file;
    uint8_t retries_done;
    an_timer cleanup_timer;
} an_idp_info_t;

typedef struct an_nbr_service_info_t_ {
    an_addr_t srvc_ip;
    an_timer cleanup_timer;
    boolean sync_done;
    uint8_t retries_done;
} an_nbr_service_info_t;

typedef enum an_nbr_bs_state_e {
    AN_NBR_BOOTSTRAP_NONE = 0,
    AN_NBR_BOOTSTRAP_STARTED,
    AN_NBR_BOOTSTRAP_REJECTED,
    AN_NBR_BOOTSTRAP_DONE,
} an_nbr_bs_state_e;

typedef enum an_ni_state_e_ {
    AN_NI_UNKNOWN = 0,
    AN_NI_OUTSIDE,
    AN_NI_CERT_EXPIRED,
    AN_NI_INSIDE,
} an_ni_state_e;

typedef enum an_nbr_cert_type_e_ {
    AN_NBR_CERT_NONE = 0,
    AN_NBR_CERT_SUDI,
    AN_NBR_CERT_DOMAIN_CERT,
} an_nbr_cert_type_e;

typedef struct an_nbr_link_spec_t {
     an_list_element_t list_elem;
 
     an_if_t local_ifhndl;
     uint8_t *nbr_if_name;
     an_timer cleanup_timer;
     an_addr_t ipaddr;        /* Link Address */ 
     an_acp_channel_info_t acp_info;
} an_nbr_link_spec_t;

typedef struct an_nbr_t_ {
    an_avl_node_t avlnode;

    an_udi_t udi;
    an_iptable_t iptable;
    
    uint8_t *device_id;
    uint8_t *domain_id;
    uint16_t num_of_links;
    an_addr_t loopbk_ipaddr; /* Actual Neighbor's address */

    /* Bootstrap Section */
    an_nbr_bs_state_e bs_state;
    uint8_t rejected_nbr_refresh_count;  /* Used for retrying a quarantined nbr */

    /* NI Section */
    an_cert_t sudi;
    an_cert_t domain_cert;
    an_ni_state_e ni_state;
    an_nbr_cert_type_e cert_type;
    an_cert_validation_t validation; 
    an_timer cert_request_timer;
    uint8_t cert_request_retries;

    /* IDP section */
    an_idp_info_t idp_info;

    /* Service Info related info */
    an_nbr_service_info_t an_nbr_srvc_list[AN_SERVICE_MAX]; 

    an_timer cleanup_timer;
    an_list_t *an_nbr_link_list;
} an_nbr_t;

typedef struct an_nbr_link_context_t {
     an_nbr_t *nbr;
     an_nbr_link_spec_t *nbr_link_data;
} an_nbr_link_context_t;


an_nbr_t* an_nbr_alloc(void);
void an_nbr_free(an_nbr_t *nbr);

boolean an_nbr_db_insert(an_nbr_t *nbr);
boolean an_nbr_db_remove(an_nbr_t *nbr);
an_nbr_t* an_nbr_db_search(an_udi_t udi);
void an_nbr_expire_nbr(an_nbr_t *nbr);
void an_nbr_remove_and_free_nbr(an_nbr_t *nbr);

void an_nbr_db_walk(an_avl_walk_f func, void *args);
void an_nbr_db_init(void);

void an_nbr_expired(an_nbr_t *nbr);
void an_nbr_set_service_info(an_nbr_t *nbr, an_service_info_t *srvc_info);

boolean an_nbr_get_addr_and_ifs(an_nbr_t *nbr, an_addr_t *addr_p, 
                    an_if_t *local_if_p, uint8_t **remote_if);

//Multiple nbr functions
//Init - create func
an_nbr_link_spec_t* an_nbr_link_db_alloc_node(void);
boolean an_nbr_link_db_create(an_nbr_t *nbr);
boolean an_nbr_link_db_insert(an_list_t *list,
                                an_nbr_link_spec_t *nbr_link_data,
                                an_if_t local_ifhndl, 
                                an_addr_t if_ipaddr, uint8_t *remote_ifhndl);

//Remove and free func
an_cerrno an_nbr_link_db_destroy(an_list_t *list);
void an_nbr_link_db_remove(an_list_t *list, 
                            an_nbr_link_spec_t *nbr_link_data);  
an_cerrno
an_nbr_link_db_stop_timer_and_remove_node(an_list_t *list,
                         const an_list_element_t *current,
                         an_nbr_link_spec_t *curr_data);
void an_nbr_link_db_free_node(an_nbr_link_spec_t *curr_nbr_link_data);

//Search func
an_nbr_link_spec_t* an_nbr_link_db_search(an_list_t *list, 
                  an_if_t ifhndl, an_addr_t addr);

//Status func
boolean an_nbr_link_db_is_empty(an_nbr_t *nbr);

//Walk func
an_cerrno
an_nbr_link_db_walk(an_list_t *list, an_list_walk_handler callback_func,
                     void *nbr_link_data);

#endif
