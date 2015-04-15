/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <an_types.h>
#include <an_if.h>
#include <an_tunnel.h>
#include <an_addr.h>
#include <an_mem.h>
#include <an_ipv6.h>
#include <an_syslog.h>
#include <an_acp.h>
#include <an_logger.h>
char *an_syslog_msg_p[MAX_AN_SYSLOG_MSG_TYPE];

void 
an_syslog_init (void)
{
    an_syslog_msg_p[AN_SYSLOG_DEVICE_NOT_ALLOWED] = 
        "Device with udi %s is not allowed by autonomic registrar in its "
        "domain %s";
    an_syslog_msg_p[AN_SYSLOG_DEVICE_ALLOWED] = 
        "Device with udi %s is allowed by autonomic registrar in its Domain ID "
        "%s with addr %s and Device ID %s";
    an_syslog_msg_p[AN_SYSLOG_DEVICE_BOOTSTRAPPED] = 
        "Device with udi %s has been boot strapped by autonomic registrar, in "
        "autonomic domain %s";
    an_syslog_msg_p[AN_SYSLOG_MASA_AUTH_FAIL] = 
        "Device with udi %s is not authorized by MASA";
    an_syslog_msg_p[AN_SYSLOG_MASA_AUDIT_LOG_FAIL] = 
        "Device with udi %s is not in the audit log of MASA";
    an_syslog_msg_p[AN_SYSLOG_MASA_NOT_CONFIG] =
        "Autonomic registrar with udi %s has no reachability to MASA-not"
        " configured, can't verify device udi %s";
    an_syslog_msg_p[AN_SYSLOG_ANRA_UP] = 
        "Configured autonomic registrar, device id %s, autonomic domain id %s";
    an_syslog_msg_p[AN_SYSLOG_ANRA_DOWN] = 
        "Disabled autonomic registrar @ device with udi %s";
    an_syslog_msg_p[AN_SYSLOG_ANRA_WHITELIST_CONFIG] =
        "Autonomic registrar with udi %s domain id %s has whitelist- will allow"
        " only these devices in autonomic network";
    an_syslog_msg_p[AN_SYSLOG_ANRA_WHITELIST_NOT_CONFIG] =
        "Autonomic registrar udi %s has no whitelist- will allow all devices";
    an_syslog_msg_p[AN_SYSLOG_ANRA_WHITELIST_FILE_ERROR] =
      "Autonomic Registrar encountered error in reading from whitelist file %s";
    //new device
    an_syslog_msg_p[AN_SYSLOG_ANRA_SIGN_VERIFY_FAIL] =
      "Signature verification of Autonomic registrar by new device has %s";
    an_syslog_msg_p[AN_SYSLOG_MASA_AUTH_TOKEN_PARSE_ERROR] =
      "Error while parsing authentication token from MASA server for "
      "device udi-%s";

    //IDP
    an_syslog_msg_p[AN_SYSLOG_IDP_INTENT_FILE_ERROR] =
       "Error in reading from intent file - %s";
    an_syslog_msg_p[AN_SYSLOG_IDP_INTENT_VER_UPDATED] =
        "Updated to a new intent version %d";
    an_syslog_msg_p[AN_SYSLOG_IDP_INTENT_VER_OLD_DISCARD] =
         "Dicarding older intent version- %d";

    //Service
    an_syslog_msg_p[AN_SYSLOG_SERVICE_LEARNT] = 
         "Autonomic service learnt, Service Type %d Service IP Addr %s";

    //UDI, SUDI, Keys
    an_syslog_msg_p[AN_SYSLOG_UDI_AVAILABLE] =
            "UDI - %s";
    an_syslog_msg_p[AN_SYSLOG_SUDI_AVAILABLE] =
            "secure UDI - %s";
    an_syslog_msg_p[AN_SYSLOG_DOMAIN_KEY_GEN_FAIL] =
            "The bootstrapping device %s failed to generate key pair for "
            "enrollment at Autonomic registrar";

    //NBR related
    an_syslog_msg_p[AN_SYSLOG_NBR_IN_DOMAIN] = 
            "nbr udi %s on interface %s is inside "
            "MY domain name %s - My device id %s";
    an_syslog_msg_p[AN_SYSLOG_NBR_OUT_DOMAIN] = 
            "nbr udi %s on interface %s is outside the autonomic domain";

    an_syslog_msg_p[AN_SYSLOG_NBR_ADDED] = 
            "nbr udi %s is added as a neighbor on interface %s";
    an_syslog_msg_p[AN_SYSLOG_NBR_LOST] = 
            "connectivity to nbr udi %s on interface %s is lost";
    an_syslog_msg_p[AN_SYSLOG_NBR_DOMAIN_CERT_VALID] =
            "Validated domain certificate of neighbor device udi %s "
            "on interface %s";
    an_syslog_msg_p[AN_SYSLOG_NBR_DOMAIN_CERT_INVALID] =
            "Invalid domain certificate of neighbor device "
            "udi %s on interface %s";
    an_syslog_msg_p[AN_SYSLOG_NBR_DOMAIN_CERT_REVOKED] =
            "Domain certificate of neighbor device "
            "udi %s on interface %s is revoked";
    an_syslog_msg_p[AN_SYSLOG_NBR_DOMAIN_CERT_EXPIRED] =
            "Domain certificate of neighbor device "
            "udi %s on interface %s is expired";
    an_syslog_msg_p[AN_SYSLOG_MY_DOMAIN_CERT_RENEWED] =
            "My Domain certificate, udi %s is renewed";
    an_syslog_msg_p[AN_SYSLOG_MY_DOMAIN_CERT_EXPIRED] =
            "My Domain certificate, udi %s has expired";

    //TLV, msg header
    an_syslog_msg_p[AN_SYSLOG_TLV_PARSE_ALIGN_ERROR] =
             "TLV parsed Len %d, Next TLV could be misaligned";
    an_syslog_msg_p[AN_SYSLOG_TLV_PARSE_LEN_INCORRECT] =
             "TLV parsed len %d > original message length %d";
    an_syslog_msg_p[AN_SYSLOG_MSG_INVALID_HEADER] =
             "Invalid message header type %d received";
    //ACP related
    //Routing - Global and per interface
    an_syslog_msg_p[AN_SYSLOG_ACP_ROUTING_GLOBAL_ENABLED] =
      "Enabled global OSPFv3 pid %d,rid %i,area %d";
    an_syslog_msg_p[AN_SYSLOG_ACP_ROUTING_INTERFACE_ENABLED] =
      "OSPF routing enabled on interface: %s, (pid %d,rid %i, area %d) ";
    an_syslog_msg_p[AN_SYSLOG_ACP_ROUTING_GLOBAL_DISABLE] =
       "Removed OSPFv3 routing globally, pid %d";

    //VRF - Global and per interface
    an_syslog_msg_p[AN_SYSLOG_ACP_VRF_GLOBAL_CREATE_SUCCESS] =
        "Autonomic VRF created globally vrf name %s, vrf id %d";
    an_syslog_msg_p[AN_SYSLOG_ACP_VRF_GLOBAL_CREATE_FAIL] =
        "Failed to create Autonomic VRF globally, vrf name %s, vrf id %d";
    an_syslog_msg_p[AN_SYSLOG_ACP_VRF_GLOBAL_REMOVE] =
        "Autonomic VRF removed globally vrf name %s, vrf id %d";
    an_syslog_msg_p[AN_SYSLOG_ACP_VRF_INTERFACE_CREATE_SUCCESS] =
        "Autonomic VRF created on interface %s, vrf name %s, vrf id %d";
    an_syslog_msg_p[AN_SYSLOG_ACP_VRF_INTERFACE_CREATE_FAIL] =
      "Failed to create autonomic VRF on interface %s, vrf name %s, vrf id %d";
    //ACP Channel
    an_syslog_msg_p[AN_SYSLOG_ACP_CHANNEL_TO_NBR_CREATED] =
    "Established ACP channel %s to neighbor %s on phy interface %s";
    an_syslog_msg_p[AN_SYSLOG_ACP_CHANNEL_TO_NBR_FAILED] =
    "Failed to create ACP channel %s to neighbor %s on phy interface %s";
    an_syslog_msg_p[AN_SYSLOG_ACP_CHANNEL_TO_NBR_REMOVED] =
    "Removed ACP channel %s to neighbor %s on phy interface %s";

    //IPSEC
    an_syslog_msg_p[AN_SYSLOG_ACP_IPSEC_TO_NBR_CREATED] =
      "Established IPSEC on ACP Channel %s to neighbor %s on phy interface %s";
    an_syslog_msg_p[AN_SYSLOG_ACP_IPSEC_TO_NBR_FAILED] =
"Failed to create IPSEC on ACP channel %s to neighbor %s on phy interface %s";
    an_syslog_msg_p[AN_SYSLOG_ACP_IPSEC_TO_NBR_REMOVED] =
                    "Removed IPSEC tunnel %s to neighbor %s, Tunnel state %d";

    //DIKE
    an_syslog_msg_p[AN_SYSLOG_ACP_DIKE_TO_NBR_CREATED] =
        "Established DIKE on ACP Channel %s to neighbor %s on phy interface %s";
    an_syslog_msg_p[AN_SYSLOG_ACP_DIKE_TO_NBR_FAILED] =
  "Failed to create DIKE on ACP channel %s to neighbor %s on phy interface %s";
    an_syslog_msg_p[AN_SYSLOG_ACP_DIKE_TO_NBR_REMOVED] =
            "Removed DIKE tunnel %s to neighbor %s, Tunnel state %d";

    // config download
    an_syslog_msg_p[AN_SYSLOG_CONFIG_DOWNLOAD_SUCCESS] =
      "Auto Config Download for the device with UDI- %s, is Success";

    an_syslog_msg_p[AN_SYSLOG_CONFIG_DOWNLOAD_FAILED] =
        "Auto Config Download for the device with Udi- %s, Failed";

    return;
}

void 
an_syslog (an_syslog_msg_e type,...)
{
    va_list args;

    va_start(args, type);
    vbuginf(an_syslog_msg_p[type], args);
    va_end(args);
    return;
}

void 
an_syslog_config_host (an_addr_t *hstaddran, char *an_vrf_name,
                                    an_idbtype *an_idb, char *discriminator)
{
            return;
}

void
an_syslog_delete_host (an_addr_t *hstaddran, char *an_vrf_name)
{
            return;
}

int
an_logger_discriminator (char* discriminator, ushort fac_includes_drops_flag,
                         char* facility_name, ushort sev_includes_drops_flag,
                         char* new_sev_group, boolean add)
{
    return (0);
}

void 
an_syslog_create_an_discriminator (void) {
    return;
}
