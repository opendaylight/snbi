/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "an_types.h"
#include "an_if.h"
#include "an.h"
#include "an_logger.h"
#include "an_timer.h"
#include "an_l2_linux.h"
#include "an_if_mgr.h"
#include "an_if_linux.h"
//#include "an_parse_linux.h" 

#define AN_LOOP_VIS_BW 8000000
char if_name_asked_for[IFNAMSIZ] = {0};
extern boolean gAN_platform_is_iol;
extern an_avl_tree  an_if_info_tree;

extern int an_sockfd;

const uint8_t *an_cd_state_str [] = {
     "Init",
     "Reuse",
     "Probing",
     "Active",
     "Inactive",
};

const uint8_t * an_get_cd_state_str (an_cd_state_e state)
{
    return (an_cd_state_str[state]);
}

inline const uint8_t * an_if_get_short_name (an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (NULL);
}

inline const uint8_t * an_if_get_name (an_if_t ifhndl)
{
#if 0   
    an_buffer_t *buffer;
    an_str_get_temp_buffer(buffer);
    if_indextoname(ifhndl, buffer->data);
    return (buffer->data);
/*
    uint8_t *if_name;
    if_name = (uint8_t*)an_malloc(sizeof(char) * (AN_STR_MAX_LEN)+1);

    if_indextoname(ifhndl, if_name);
        return (NULL);
    }
    return(if_name);
// Free this "if_name" in caller.
*/
    char *if_name;
    if_name = malloc(IFNAMSIZ); 

    if_indextoname(ifhndl, if_name);

    return (if_name);
#endif   
    if_indextoname(ifhndl, if_name_asked_for);
    return (if_name_asked_for);
}

inline boolean an_if_is_up (an_if_t ifhndl)
{
    uint8_t *iface_name = NULL;
    struct ifreq ifr;

    if (!ifhndl) {
        return (FALSE);
    }

    iface_name = (uint8_t *)an_if_get_name(ifhndl); 
    /* get interface name */
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    /* Read interface flags */
    if (ioctl(an_sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        return (FALSE);
    }
    if ((ifr.ifr_flags & IFF_UP)) {
        return (TRUE);
    }
    return (FALSE);
}

an_if_t 
an_if_check_vlan_exists (uint32_t unit) 
{     
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

boolean
an_if_check_loopback_exists (uint32_t unit) 
{     
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE); 
}

void
an_if_platform_specific_cfg (an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

boolean an_if_bring_up (an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

inline boolean an_if_is_tunnel (an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}

boolean
an_if_is_loopback (an_if_t ifhndl)
{   
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}

void
an_if_walk (an_if_walk_func func, void *data)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

boolean
an_if_is_ethernet (an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (FALSE);
}

boolean
an_if_make_volatile (an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (TRUE);
}

an_if_t
an_if_create_loopback (uint32_t unit)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return (0);
}

an_if_t
an_get_autonomic_loopback_ifhndl(void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (0);
}

void
an_if_remove_loopback (an_if_t lb_ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
            return;
}

 /*
  * This function is used to check whether the idb is loopback idb
  * or not. This is used while recycling the idb.
  */
boolean
an_if_recycle_matcher (an_idbtype *idb)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
   return FALSE;
}

/* This function clears already created idb sub-blocks. 
 */

void 
clear_idb_subblocks (an_idbtype *idb)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
        return;
}

uint8_t* 
an_if_get_l2_mac_addr (an_hwidbtype *hwidb)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (NULL);
} 

void 
an_if_set_svi_mac_addr (an_hwidbtype *hwidb, uint8_t* l2_mac)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return;
}

an_idbtype * an_if_number_to_swidb(an_if_t ifhndl)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
   return(NULL);
}

void an_set_if_vlanid (an_if_info_t *an_if_info, ushort vlanid)
{
    an_if_info->vlan_info.vlanid = vlanid;
    return;
}

void an_set_if_inner_vlanid (an_if_info_t *an_if_info, ushort inner_vlanid)
{
    an_if_info->vlan_info.inner_vlanid = inner_vlanid;
    return;
}

boolean
an_should_bring_up_interfaces (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
    return (FALSE);
}

void
an_if_services_init (void)
{
   an_cerrno rc = EOK;

    rc = an_avl_init(&an_if_info_tree, an_if_info_compare);
    if (CERR_IS_NOTOK(rc)) {
        DEBUG_AN_LOG(AN_LOG_ND_EVENT, AN_DEBUG_MODERATE, NULL,
                 "\n%s AN IF DB Init Failed", an_nd_event);
    }
}

void
an_if_services_uninit (void)
{
printf("\n[SRK_DBG] %s():%d - START ....",__FUNCTION__,__LINE__);
   return;
}


