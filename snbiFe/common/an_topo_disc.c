/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "../al/an_types.h"
char *global_url_str = NULL;

#if 0
#include "../al/an_addr.h"
#include "an_nbr_db.h"
#include "../al/an_ipv6.h"
#include "../al/an_if.h"
#include "an_topo_disc.h"
#include "an_ni.h"
#include "an_bs.h"
#include "an_msg_mgr.h"
#include "../al/an_pak.h"
#include "../al/an_mem.h"
#include "../al/an_topo.h"
//#include <kernel/mki/include/signal.h>
//#include <ipv6_forwarding/include/ipv6_forwarding.h>
#include "../al/an_str.h"
#include <kernel/mki/include/signal.h>
#include <ipv6_forwarding/include/ipv6_forwarding.h>

//static char *tdp_proc_name = "TDP Discovery";
watched_queue *tdp_message_q = NULL;
//pid_t tdp_pid = NO_PROCESS;
char *global_url_str = NULL;

/*
 * The initiator address to which the response 
 * should always be directed to. We assume
 * there is always only one initiator at any given point of time.
 */
an_v6addr_t global_initiator_addr;
time_t      global_topo_request_id = 0;
an_if_t     global_ifhndl;

#if 0
char*
topo_event_str (an_topo_event_t topo_event) 
{
    switch (topo_event) {

    case TOPO_EVENT_UP:
        return "Up";
    case TOPO_EVENT_DOWN:
        return "Down";
    case TOPO_EVENT_DOMAIN_OUTSIDE_UP:
        return "Outside Domain UP";
    case TOPO_EVENT_DOMAIN_OUTSIDE_DOWN:
        return "Outside Domain DOWN";
    case TOPO_EVENT_UNSECURE_UP:
        return "Un-secure Node UP";
    case TOPO_EVENT_UNSECURE_DOWN:
        return "Un-secure Node DOWN";
    default:
        break;
    }
    return "Unknown";
}
#endif

void
an_topo_free_resp_msg (topo_resp_message *resp_msg)
{
   an_free_guard(resp_msg);
}
  
void
an_notify_edge (topo_resp_message *resp_msg, an_if_t ifhndl)
{
    topo_port_identity_t *loc_port = NULL, *peer_port = NULL;
    topo_node_identity_t *loc_node = NULL, *peer_node = NULL;
    topo_proto_info_t proto_info;

    an_log(AN_LOG_TOPO, "\n%sStart notify new Edge", an_topo_prefix);

    /*
     * Update Topology Info.
     */
    proto_info.protocols = CDP_TOPOLOGY;

    /* 
     * Update Local Port and Local Node Info
     */
    loc_port = an_malloc_guard(sizeof(topo_port_identity_t),
                               "Event Port Identity");
    if (!loc_port) {
        return;
    }
    an_memset_guard_s(loc_port, 0, sizeof(topo_port_identity_t));

    loc_node = an_malloc_guard(sizeof(topo_node_identity_t),
                            "Event Node identity");
    if (!loc_node) {
        an_free_guard(loc_port);
        return;
    }
    an_memset_guard_s(loc_node, 0, sizeof(topo_node_identity_t));
    
    loc_port->topo_node_ptr = loc_node;

    loc_port->port_name = (char *)an_malloc_guard(LOCAL_PORT_NAME_LEN,
                                               "Port Name String");
    if (!loc_port->port_name) {
        an_free_guard(loc_port->topo_node_ptr);
        an_free_guard(loc_port);
        return;
    }
    an_strncpy_s(loc_port->port_name, LOCAL_PORT_NAME_LEN, resp_msg->local_port, 
             LOCAL_PORT_NAME_LEN -1);

    loc_node->node_name = an_malloc_guard(LOCAL_NODE_NAME_LEN,
                                       "Node Name String");
    if (!loc_node->node_name) {
        an_free_guard(loc_port->topo_node_ptr);
        an_free_guard(loc_port);
        return;
    }

    an_strncpy_s(loc_node->node_name, LOCAL_NODE_NAME_LEN, resp_msg->local_node,
             LOCAL_NODE_NAME_LEN - 1);

    /*
     * Update Peer Port and Peer Node Info
     */
    peer_port = an_malloc_guard(sizeof(topo_port_identity_t),
                            "Event Peer Port Identity");
    if (!peer_port) {
        an_free_guard(loc_port->topo_node_ptr);
        an_free_guard(loc_port);
        return;
    }        
    an_memset_guard_s(peer_port, 0, sizeof(topo_port_identity_t));

    peer_node = an_malloc_guard(sizeof(topo_node_identity_t),
                             "Event Peer Node identity");
    if (!peer_node) {
        an_free_guard(peer_port);
        an_free_guard(loc_port->topo_node_ptr);
        an_free_guard(loc_port);
        return;
    }
    an_memset_guard_s(peer_node, 0, sizeof(topo_node_identity_t));
    peer_port->topo_node_ptr = peer_node;

    peer_port->port_name = (char *)an_malloc_guard(PEER_PORT_NAME_LEN,
                                               "Port Name String");
    if (!peer_port->port_name) {
        goto cleanup;   
    }
    an_strncpy_s(peer_port->port_name, PEER_PORT_NAME_LEN, 
             resp_msg->peer_port, PEER_PORT_NAME_LEN - 1);

    peer_node->node_name = (char *)an_malloc_guard(PEER_NODE_NAME_LEN,
                                               "Port Name String");
    if (!peer_node->node_name) {
        goto cleanup;
    }

    an_strncpy_s(peer_node->node_name, PEER_NODE_NAME_LEN,
             resp_msg->peer_node, PEER_NODE_NAME_LEN - 1);

    an_log(AN_LOG_TOPO, "\n%sNotify %s - ", an_topo_prefix,
            topo_event_str(resp_msg->topo_event));
    an_log(AN_LOG_TOPO, "ID: %u,", resp_msg->topo_request_id);
    an_log(AN_LOG_TOPO, " Peer : %s/%s,",
            resp_msg->peer_node, resp_msg->peer_port);
    an_log(AN_LOG_TOPO, " Local : %s/%s,", 
            resp_msg->local_node, resp_msg->local_port);
#if 0 // [ToDo] : will be fixed shortly
    /*
     * Notify Topology Discovery
     */
    topo_notify_events(TOPO_DISC_PEER_PORT, loc_port, peer_port,
                       &proto_info, resp_msg->topo_event);
#endif 
cleanup:

    if (loc_port->topo_node_ptr) {
        an_free_guard(loc_port->topo_node_ptr);
    }
    if (loc_port) {
        an_free_guard(loc_port);
    }
    if (peer_port->topo_node_ptr) {
        an_free_guard(peer_port->topo_node_ptr);
    }
    if (peer_port) {
        an_free_guard(peer_port);
    }
    return;
}

#if 0
void
topo_send_message (an_nbr_t *nbr, topo_message *message, an_pak_t *pak)
{
  an_addr_t nbr_addr = AN_ADDR_ZERO;
  an_v6addr_t v6_nhop = AN_V6ADDR_ZERO;
  an_if_t nbr_ifhndl = 0;

  an_nbr_get_addr_and_ifs(nbr, &nbr_addr, &nbr_ifhndl, NULL);  
  v6_nhop = an_addr_get_v6addr(nbr_addr);

  an_log(AN_LOG_TOPO, "\n%sSending Msg to %s on %s",an_topo_prefix, 
          an_addr_get_string(&nbr_addr),
          an_if_get_name(nbr_ifhndl));
  ipv6_set_prerouted_params(pak, if_number_to_swidb(nbr_ifhndl),
                            &v6_nhop, FALSE);
  ipv6_write(pak);

  if (message) {
      an_free_guard(message);
  }
}
#endif

topo_message*
topo_prepare_message (an_nbr_t *nbr, an_pak_t **pak_out, topo_msg_t msg_type) 
{
    topo_message *message = NULL;
    uint8_t  *msg_block = NULL;
    an_pak_t *pak       = NULL; 
    uint32_t pak_len    = 0;
    an_v6addr_t src_v6addr, dst_v6addr;
    an_addr_t an_addr = AN_ADDR_ZERO, nbr_addr = AN_ADDR_ZERO;
    int indicator1 = 0;
    int indicator2 = 0;
    int indicator3 = 0;
    int indicator4 = 0;

    an_memcmp_s(&global_initiator_addr, sizeof(an_v6addr_t), 
               (void *)&AN_V6ADDR_ZERO, sizeof(an_v6addr_t), &indicator1);
    if (!indicator1) {
        an_log(AN_LOG_TOPO, "\n%sPrepare TDP request, No Initiator Addr",
                an_topo_prefix);
        return (NULL);
    }
    if (an_bs_nbr_get_state(nbr) == AN_NBR_BOOTSTRAP_REJECTED) {
        an_log(AN_LOG_TOPO, "\n%sNeighbor in Rejected state", an_topo_prefix);
        return (NULL);
    }
    if (!global_topo_request_id) {
        an_log(AN_LOG_TOPO, "\n%sPrepare TDP request, No global ID", an_topo_prefix);
        return (NULL);
    }
    message = an_malloc_guard(TOPO_DISC_MSG_LEN, "Topo Disc");
    if (!message) {
        an_log(AN_LOG_TOPO, "\n%sTDP Message allocation failed", an_topo_prefix);
        return (NULL);
    }   
    message->msg_type        = msg_type;
    message->initiator_addr  = global_initiator_addr;
    message->topo_request_id = global_topo_request_id;

    global_topo_request_id = message->topo_request_id;

    an_log(AN_LOG_TOPO, "\n%sPrepare REQ ", an_topo_prefix);
  
    an_log(AN_LOG_TOPO, " %u,", message->msg_type);
    an_log(AN_LOG_TOPO, " %u,", message->topo_request_id);

    an_addr_set_from_v6addr(&an_addr, message->initiator_addr);
    an_log(AN_LOG_TOPO, "Initiator Addr %s", 
                         an_addr_get_string(&an_addr));

    pak_len = sizeof(topo_message) + sizeof(an_ipv6_hdr_t);

    pak = getbuffer(pak_len);

    if (!pak) {
        an_log(AN_LOG_PAK | AN_LOG_ERR, "\n%sFailed to alloc pak", 
                an_topo_prefix);
        an_free_guard(message);
        return (NULL);
    }
    an_log(AN_LOG_PAK, "\n%spak len %u, Topo %u", an_topo_prefix,
            pak_len, sizeof(topo_message));
    an_pak_set_datagram_size(pak, pak_len);
    an_pak_set_linktype(pak, LINK_IPV6);

    an_pak_set_iptable(pak, an_get_iptable());

    an_nbr_get_addr_and_ifs(nbr, &nbr_addr, NULL, NULL);

    src_v6addr = 
        an_addr_get_v6addr(
            an_ipv6_get_best_source_addr(nbr_addr, nbr->iptable));

    dst_v6addr = an_addr_get_v6addr(nbr_addr);
    an_memcmp_s(&dst_v6addr, sizeof(an_v6addr_t), 
               (void *)&AN_V6ADDR_ZERO, sizeof(an_v6addr_t), &indicator2);

    if (!indicator2) {
        an_log(AN_LOG_TOPO | AN_LOG_ERR, "\n%sDST NULL", an_topo_prefix);
        an_free_guard(message);
        datagram_done(pak);
        return (NULL);
    }
    an_memcmp_s(&src_v6addr, sizeof(an_v6addr_t), 
               (void *)&AN_V6ADDR_ZERO, sizeof(an_v6addr_t), &indicator3);

    if (!indicator3) {
        an_log(AN_LOG_TOPO | AN_LOG_ERR, "\n%sSRC NULL", an_topo_prefix);
        an_free_guard(message);
        datagram_done(pak);
        return (NULL);
    }
    an_memcmp_s(&src_v6addr, sizeof(an_v6addr_t), 
               &dst_v6addr, sizeof(an_v6addr_t), &indicator4);
    if (!indicator4) {
        an_log(AN_LOG_TOPO | AN_LOG_ERR, "\n%sSRC & DST Same", an_topo_prefix);
        an_free_guard(message);
        datagram_done(pak);
        return (NULL);
    }

    /* setup the ipv6 header */
    an_ipv6_hdr_init(an_pak_get_network_hdr(pak),
            AN_DEFAULT_TOS,
            AN_DEFAULT_FLOW_LABEL,
            sizeof(topo_message),
            TDP_PROT,
            AN_DEFAULT_HOP_LIMIT,
            &src_v6addr,
            &dst_v6addr);

    /* get pointer to message block in the packet */
    msg_block = an_pak_get_network_hdr(pak) + sizeof(an_ipv6_hdr_t);

    if (!msg_block) {
        an_log(AN_LOG_PAK | AN_LOG_ERR, "\n%sCouldn't find msg block",
                an_topo_prefix);
        an_free_guard(message);
        datagram_done(pak);
        return (NULL);
    }
    an_memcpy_s(msg_block, sizeof(topo_message), message, sizeof(topo_message)); 

    *pak_out = pak;
    return (message);
}

void
topo_req_nbr_message (an_nbr_t *nbr)
{
    topo_message *message = NULL;
    an_pak_t *pak = NULL;

    message = topo_prepare_message(nbr, &pak, TOPO_REQ);
    if (!message) {
        an_log(AN_LOG_TOPO, "\n%sMessage preparation failed", an_topo_prefix);
        return;
    }

    topo_send_message(nbr, message, pak);
}

void
topo_req_nbr (an_nbr_t *nbr)
{
    if (!nbr) {
        an_log(AN_LOG_TOPO, "\n%sNo Neighbors, topo request nbr",
                an_topo_prefix);
        return;
    }
    topo_req_nbr_message(nbr);
}

boolean
topo_request (an_avl_node_t *node, void *args)
{
    an_if_t              ifhndl = 0, nbr_ifhndl = 0;
    topo_call_back_param *topo_cbp;
    an_nbr_t             *nbr = (an_nbr_t *)node;

    if (!nbr) {
        an_log(AN_LOG_TOPO, "\n%sNo Neighbors, topo_request", an_topo_prefix);
        return (FALSE);
    }
    topo_cbp = (topo_call_back_param *)args;
    /* 
     * Request can be filtered based on IP address 
     * range or a particular Domain Name.
     */
    if (topo_cbp) {
        ifhndl = topo_cbp->ifhndl;
    }

    if (!an_nbr_get_addr_and_ifs(nbr, NULL, &nbr_ifhndl, NULL)) {
        return (FALSE);
    }

    if (ifhndl) {
        if (nbr_ifhndl != ifhndl) {
            topo_req_nbr(nbr);
        } else {
            an_log(AN_LOG_TOPO, "\n%sNot sending topo req on %s",
                    an_topo_prefix, an_if_get_name(ifhndl));
        }
    } else {
        topo_req_nbr(nbr);
    }
    
    return (TRUE);
}

#if 0
void
topo_send_resp_message (topo_resp_message *resp_msg, an_pak_t *pak)
{
    if (resp_msg) {
        an_free_guard(resp_msg);
    }
    ipv6_write(pak);
}
#endif

topo_resp_message *
topo_prepare_resp_msg (an_nbr_t *nbr, 
                       an_pak_t **pak_out,
                       topo_event_t topo_event) 
{
    uint8_t  *msg_block = NULL;
    an_pak_t *pak       = NULL; 
    uint32_t pak_len    = 0;
    uint8_t  *dev_id     = NULL;
    an_if_t nbr_ifhndl  = 0;
    uint8_t *nbr_if_name = NULL;
    int indicator1 = 0;
    int indicator2 = 0;

    an_v6addr_t src_v6addr = AN_V6ADDR_ZERO;
    an_addr_t an_addr      = AN_ADDR_ZERO;
    an_addr_t an_addr_src  = AN_ADDR_ZERO;
    an_addr_t device_ip    = AN_ADDR_ZERO;
    topo_resp_message *resp_msg;

    *pak_out = NULL;
    an_memcmp_s(&global_initiator_addr, sizeof(an_v6addr_t),
         (void *)&AN_V6ADDR_ZERO, sizeof(an_v6addr_t), &indicator1);

    if (!indicator1) {
        an_log(AN_LOG_TOPO, "\n%sRESP failed - No initiator addr", 
                an_topo_prefix);
        return (NULL);
    }
    if (!nbr) {
        an_log(AN_LOG_TOPO, "\n%sRESP failed - No nbr", an_topo_prefix);
        return (NULL);
    }
    if (!an_nbr_get_addr_and_ifs(nbr, NULL, &nbr_ifhndl, &nbr_if_name)) {
        return (NULL);
    }
    dev_id = an_get_device_id();
    if (!dev_id) {
        an_log(AN_LOG_TOPO, "\n%sRESP failed - null device id", an_topo_prefix);
        return (NULL);
    }
    if (an_bs_nbr_get_state(nbr) != AN_NBR_BOOTSTRAP_REJECTED) {
        if (!nbr->device_id) {
            an_log(AN_LOG_TOPO, "\n%sRESP failed - null device id",
                    an_topo_prefix);
            return (NULL);
        }
    }
    device_ip  = an_get_device_ip();
    src_v6addr = an_addr_get_v6addr(device_ip);
    an_memcmp_s(&src_v6addr, sizeof(an_v6addr_t), 
               (void *)&AN_V6ADDR_ZERO, sizeof(an_v6addr_t), &indicator2);

    if (!indicator2) {
        an_log(AN_LOG_TOPO, "\n%sRESP No Source Addr", an_topo_prefix);
        return (NULL);
    }

    resp_msg = an_malloc_guard(TOPO_RESP_MSG_LEN, "Topo Disc RESP");
    if (!resp_msg) {
        an_log(AN_LOG_TOPO, "\n%sMessage RESP allocation failed", an_topo_prefix);
        return (NULL);
    }   
    resp_msg->msg_type        = TOPO_RESP;
    resp_msg->topo_request_id = global_topo_request_id;
    resp_msg->topo_event      = topo_event;

    if (nbr) {
        an_log(AN_LOG_TOPO, "\n%sDevice id %s", an_topo_prefix, nbr->device_id);

        if (topo_event == TOPO_EVENT_DOMAIN_OUTSIDE_UP) {
            an_memcpy_s(resp_msg->peer_node, PEER_NODE_NAME_LEN-1, 
                                     nbr->udi.data, nbr->udi.len);
        } else {
            an_memcpy_s(resp_msg->peer_node, PEER_NODE_NAME_LEN-1, 
                                nbr->device_id, an_strlen(dev_id)+1);
        }
        an_memcpy_s(resp_msg->peer_port, PEER_PORT_NAME_LEN-1, nbr_if_name,
                                                  an_strlen(nbr_if_name)+1);
    } 
    an_memcpy_s(resp_msg->local_node, LOCAL_NODE_NAME_LEN-1, an_get_device_id(),
                                                            an_strlen(dev_id)+1);

    an_memcpy_s(resp_msg->local_port, LOCAL_PORT_NAME_LEN-1,
               an_if_get_name(nbr_ifhndl), LOCAL_PORT_NAME_LEN-1);
    
    an_log(AN_LOG_TOPO, "\n%sRESP: ", an_topo_prefix); 
    an_log(AN_LOG_TOPO, "ID: %u,", resp_msg->topo_request_id);
    an_log(AN_LOG_TOPO, " PEER : %s/%s,", 
           resp_msg->peer_node, resp_msg->peer_port);
    an_log(AN_LOG_TOPO, " Local : %s/%s,", 
           resp_msg->local_node, resp_msg->local_port);

    pak_len = sizeof(topo_resp_message) + sizeof(an_ipv6_hdr_t);

    pak = getbuffer(pak_len);

    if (!pak) {
        an_log(AN_LOG_PAK | AN_LOG_ERR, "\n%sFailed to alloc pak",
                an_topo_prefix);
        return (NULL);
    }
    an_log(AN_LOG_PAK, "\n%sPak len %u, Topo %u", 
            an_topo_prefix, pak_len, sizeof(topo_resp_message));

    an_pak_set_datagram_size(pak, pak_len);
    an_pak_set_linktype(pak, LINK_IPV6);

    an_pak_set_iptable(pak, an_get_iptable());

    an_addr_set_from_v6addr(&an_addr_src, src_v6addr);
    an_log(AN_LOG_TOPO, "\n%sRESP: Source %s", an_topo_prefix,
            an_addr_get_string(&an_addr_src));

    an_addr_set_from_v6addr(&an_addr, global_initiator_addr);
    an_log(AN_LOG_TOPO, " Initiator %s", an_addr_get_string(&an_addr));
    /* setup the ipv6 header */
    an_ipv6_hdr_init(an_pak_get_network_hdr(pak),
            AN_DEFAULT_TOS,
            AN_DEFAULT_FLOW_LABEL,
            sizeof(topo_resp_message),
            TDP_PROT,
            AN_DEFAULT_HOP_LIMIT,
            &src_v6addr,
            &global_initiator_addr);

    /* get pointer to message block in the packet */
    msg_block = an_pak_get_network_hdr(pak) + sizeof(an_ipv6_hdr_t);

    if (!msg_block) {
        an_log(AN_LOG_PAK | AN_LOG_ERR, "\n%sCouldn't find msg block", 
                an_topo_prefix);
        return (NULL);
    }
    an_memcpy_s(msg_block, sizeof(topo_resp_message), resp_msg, 
                                               sizeof(topo_resp_message)); 

    *pak_out = pak;
    return (resp_msg);
}

boolean
tdp_respond_back_to_initiator (an_avl_node_t *node, void *args)
{
    an_pak_t             *pak = NULL;
    an_if_t              ifhndl;
    topo_call_back_param *topo_cbp = NULL;
    topo_resp_message    *resp = NULL;

    an_nbr_t *nbr = (an_nbr_t *)node;

    topo_cbp        = (topo_call_back_param *)args;

    ifhndl          = topo_cbp->ifhndl;

    an_log(AN_LOG_TOPO, "\n%sRESP ", an_topo_prefix);

    if (an_bs_nbr_get_state(nbr) != AN_NBR_BOOTSTRAP_REJECTED) {
        an_log(AN_LOG_TOPO, "\n%sRESP Domain Inside", an_topo_prefix);
        resp = topo_prepare_resp_msg(nbr, &pak, TOPO_EVENT_UP);

    } else if (an_bs_nbr_get_state(nbr) == AN_NBR_BOOTSTRAP_REJECTED) {
        an_log(AN_LOG_TOPO, "\n%sRESP Domain Outside", an_topo_prefix);
        resp = topo_prepare_resp_msg(nbr, &pak, TOPO_EVENT_DOMAIN_OUTSIDE_UP);
    }

    if (resp == NULL) {
        an_log(AN_LOG_TOPO, "\n%sRESP Preparation Failed", an_topo_prefix);
        if (ifhndl) {
            global_ifhndl = ifhndl;
        }
        an_log(AN_LOG_TOPO, "\n%sRESP Domain Error", an_topo_prefix);
        return (FALSE);
    }
    topo_send_resp_message(resp, pak);

    return (TRUE);
}

void
tdp_forward_topo_req (topo_message *req_msg, an_if_t ifhndl)
{
    topo_call_back_param topo_cbp;

    an_log(AN_LOG_TOPO, "\n%sForward requests", an_topo_prefix);

    topo_cbp.ifhndl          = ifhndl;
    topo_cbp.topo_request_id = 0; 

   /*
    *  Update the global initiator address for all response messages
    */
    global_initiator_addr = req_msg->initiator_addr;

    if (req_msg->topo_request_id != global_topo_request_id) {
        an_nbr_db_walk(topo_request, (void *)&topo_cbp);
        global_topo_request_id = req_msg->topo_request_id;
    }
}

void
tdp_handle_topo_req (char *message, an_if_t ifhndl)
{
    topo_message *req_msg;
    topo_call_back_param topo_cbp;
    an_addr_t an_addr; 

    req_msg = (topo_message *)message;
    an_log(AN_LOG_TOPO, "\n%sHandle Req Message", an_topo_prefix);
  
    an_log(AN_LOG_TOPO, " REQ Msg %u,", req_msg->msg_type);
    an_log(AN_LOG_TOPO, " ID %u,", req_msg->topo_request_id);

    an_addr_set_from_v6addr(&an_addr, req_msg->initiator_addr);

    an_log(AN_LOG_TOPO, " Initiator %s",
                         an_addr_get_string(&an_addr));

    topo_cbp.topo_request_id = req_msg->topo_request_id;
    topo_cbp.ifhndl          = ifhndl;
    global_initiator_addr    = req_msg->initiator_addr;

    an_nbr_db_walk(tdp_respond_back_to_initiator, (void *)&topo_cbp);

    tdp_forward_topo_req(req_msg, ifhndl);
}

void
topo_nbr_connect (an_nbr_t *nbr)
{
    an_log(AN_LOG_TOPO, "\n%sNew Neighbor connected", an_topo_prefix);

    topo_req_nbr(nbr);
}

void
topo_nbr_update (an_nbr_t *nbr, topo_event_t topo_event)
{
    an_pak_t *pak_out;
    topo_resp_message *resp_msg;

    an_log(AN_LOG_TOPO, "\n%sNeighbor Update %s", an_topo_prefix,
            topo_event_str(topo_event));

    resp_msg = topo_prepare_resp_msg(nbr, &pak_out, topo_event);

    if (!resp_msg) {
        an_log(AN_LOG_TOPO, "\n%sPrepare Resp Failed Outside Domain",
                an_topo_prefix);
        return;
    }
    topo_send_resp_message(resp_msg, pak_out);
}

void
topo_nbr_disconnect (an_nbr_t *nbr)
{
    an_pak_t *pak_out;
    topo_resp_message *resp_msg;

    an_log(AN_LOG_TOPO, "\n%sNeighbor Disconnected", an_topo_prefix);

    resp_msg = topo_prepare_resp_msg(nbr, &pak_out, TOPO_EVENT_DOWN);

    if (!resp_msg) {
        an_log(AN_LOG_TOPO, "\n%sPrepare Resp Failed", an_topo_prefix);
        return;
    }
    topo_send_resp_message(resp_msg, pak_out);
}

void
tdp_handle_topo_resp (char *message, an_if_t ifhndl)
{
    topo_resp_message *resp_msg;

    an_log(AN_LOG_TOPO, "\n%sRESPONSE Message", an_topo_prefix);

    resp_msg = (topo_resp_message *)message;
    an_notify_edge(resp_msg, ifhndl);
}

void
tdp_handle_incoming_topo_msg (an_pak_t *pak)
{
    an_if_t    ifhndl     = 0;
    char       *msg_block = NULL;
    topo_msg_t msg_type   = TOPO_REQ;

    ifhndl = an_pak_get_input_if(pak);
    msg_block = (char *)(an_pak_get_network_hdr(pak) + AN_IPV6_HDR_SIZE);
   
    if (!msg_block) {
        an_log(AN_LOG_PAK, "\n%sNo Msg block in topo msg", an_topo_prefix);
        return;
    }
    msg_type = GETLONG(msg_block);

    switch (msg_type) {
    case TOPO_REQ:
        tdp_handle_topo_req(msg_block, ifhndl);
        break;
    case TOPO_RESP:
        tdp_handle_topo_resp(msg_block, ifhndl);
        break;
    default:
        an_log(AN_LOG_TOPO, "\n%sInvalid msg %u", an_topo_prefix, msg_type);

        break;
    }
    return;
}

void
tdp_handle_message_events (void)
{
    an_log(AN_LOG_PAK, "\n%sHandle Message events", an_topo_prefix);
}

void
tdp_handle_queue_events (void)
{
    paktype *pak = process_dequeue(tdp_message_q);
    if (pak) {
        an_log(AN_LOG_PAK, "\n%sDequeued packet", an_topo_prefix);
        tdp_handle_incoming_topo_msg(pak);
        datagram_done(pak);
    }
    return;
}

#if 0
static void
tdp_enqueue_pkt (paktype *pak)
{
    if (process_enqueue(tdp_message_q, pak)) {
        an_log(AN_LOG_PAK, "\n%sEnqueued packet", an_topo_prefix);
        return;
    }
}
#endif

void
topo_disc_adv (void)
{
    topo_call_back_param topo_cbp;

    an_log(AN_LOG_TOPO, "\n%sADV Respond back to initiator", an_topo_prefix);

    topo_cbp.topo_request_id = global_topo_request_id;
    topo_cbp.ifhndl          = global_ifhndl;
    //global_initiator_addr    = global_initiator_addr; SA noise warning

    an_nbr_db_walk(tdp_respond_back_to_initiator, (void *)&topo_cbp);
}

void
topo_disc_initiate (void)
{
    an_addr_t device_ip = AN_ADDR_ZERO;

    an_log(AN_LOG_TOPO, "\n%sTDP Initiate ", an_topo_prefix);

    an_log(AN_LOG_TOPO, "\nAN TDP::Initiating TDP time %u", global_topo_request_id);
    if (global_topo_request_id) {
        an_log(AN_LOG_TOPO, "\n TDP AN: Already Initiated ..");
    } else {
        global_topo_request_id = time(NULL);
    }

    device_ip             = an_get_device_ip();
    global_initiator_addr = an_addr_get_v6addr(device_ip); 
    /*
     * Walk through all the neigbors and request topology information
     */
    an_nbr_db_walk(topo_request, NULL);
}

#if 0
static void
tdp_teardown (int signal, int dummy1, void *dummy2, char *dummy3)
{
    an_log(AN_LOG_TOPO, "\n%sTDP Teardown ", an_topo_prefix);
    return;
}
#endif 

void
an_notify_masa_application (char *url_str)
{
    topo_resp_message *resp_msg;
    an_if_t ifhndl = 0;

    resp_msg = an_malloc_guard(TOPO_RESP_MSG_LEN, "Topo Disc RESP");
    if (!resp_msg) {
        an_log(AN_LOG_TOPO, "\n%sRESP allocation failed", an_topo_prefix);
        return ;
    }   
    resp_msg->msg_type        = TOPO_RESP;
    resp_msg->topo_request_id = global_topo_request_id;
    resp_msg->topo_event      = TOPO_EVENT_UNSECURE_UP;

    an_log(AN_LOG_TOPO, "\n%sDevice MASA", an_topo_prefix);

    an_memcpy_s(resp_msg->peer_node, PEER_NODE_NAME_LEN-1, "MASA Server",
                                                    PEER_NODE_NAME_LEN-1);
    an_memcpy_s(resp_msg->peer_port, PEER_PORT_NAME_LEN-1, url_str,
                                                    PEER_PORT_NAME_LEN-1);

    an_memcpy_s(resp_msg->local_node, LOCAL_NODE_NAME_LEN-1, an_get_device_id(),
                                                         LOCAL_NODE_NAME_LEN-1);

    an_memcpy_s(resp_msg->local_port, LOCAL_PORT_NAME_LEN-1, "Client", 
                                                    LOCAL_PORT_NAME_LEN-1);

    an_notify_edge(resp_msg, ifhndl);
}

void
an_notify_nms_application (void)
{
    topo_resp_message *resp_msg;
    an_if_t ifhndl = 0;

    resp_msg = an_malloc_guard(TOPO_RESP_MSG_LEN, "Topo Disc RESP");
    if (!resp_msg) {
        an_log(AN_LOG_TOPO, "\n%sMessage RESP allocation failed", an_topo_prefix);
        return ;
    }   
    resp_msg->msg_type        = TOPO_RESP;
    resp_msg->topo_request_id = global_topo_request_id;
    resp_msg->topo_event      = TOPO_EVENT_UNSECURE_UP;

    an_log(AN_LOG_TOPO, "\n%sNMS", an_topo_prefix);

    an_memcpy_s(resp_msg->peer_node, PEER_NODE_NAME_LEN-1, "NMS ",
                                             PEER_NODE_NAME_LEN-1);
    an_memcpy_s(resp_msg->peer_port, PEER_PORT_NAME_LEN-1, "Client App ",
                                                    PEER_PORT_NAME_LEN-1);

    an_memcpy_s(resp_msg->local_node, LOCAL_NODE_NAME_LEN-1, an_get_device_id(),
                                                         LOCAL_NODE_NAME_LEN-1);

    an_memcpy_s(resp_msg->local_port, LOCAL_PORT_NAME_LEN-1, "Server", 
                                                         LOCAL_PORT_NAME_LEN-1);

    an_notify_edge(resp_msg, ifhndl);
}

void
topo_disc_get_next_node (topo_proto_info_t *topo_proto_info,
                         topo_node_identity_t *prev_node,
                         topo_node_identity_t **_node_identity,
                         topo_retval_t *topo_retval)
{
    uint8_t *dev_id = NULL;
    an_log(AN_LOG_TOPO, "\n%sGet next node from application", an_topo_prefix);
    
    dev_id = an_get_device_id();
    
    if (dev_id) {
        an_log(AN_LOG_TOPO, "\n%sDevice id %s", an_topo_prefix, dev_id);
        topo_disc_initiate();
        an_notify_nms_application();
        an_notify_masa_application(global_url_str);
    }
}
/* To be uncommented when we use TDP proc.*/
#if 0
static void
tdp_process (void)
{
    ulong major = 0;
    ulong minor = 0;

    if (!tdp_message_q) {
        ipv6_attach(TDP_PROT, tdp_enqueue_pkt, "tdp_enqueue_pkt");

        tdp_message_q = create_watched_queue("TDP Msg Q", 0, 1);
        process_watch_queue(tdp_message_q, ENABLE, RECURRING);

        /*
         * When the application connects, this API is
         * being called and this can kick start the topology
         * discovery process. TDP_TOPOLOGY doesn't exist in
         * the application side yet, hence using CDP_TOPOLOGY for now.
         */
#if 0 // [ToDo] : will be fixed shortly
        reg_add_topo_get_next_node(CDP_TOPOLOGY,
                                   topo_disc_get_next_node, 
                                   "topo_disc_get_next_node");
#endif
    }

    signal_permanent(SIGEXIT, tdp_teardown);

    while (TRUE) {

        process_wait_for_event();

         while (process_get_wakeup(&major, &minor)) {
            switch(major) {
            case MESSAGE_EVENT:
                tdp_handle_message_events();
                break;

            case QUEUE_EVENT:
                tdp_handle_queue_events();
                break;

            case DIRECT_EVENT:
            case BOOLEAN_EVENT:
                break;

            default:
                an_log(AN_LOG_TOPO, "\n%sUnexpected event", an_topo_prefix);
                break;
            }
        }
    }
}
#endif

void
topo_disc_init (void)
{
    /* Uncomment this section when TDP proc is reqd.
    if (tdp_pid == NO_PROCESS) {
        tdp_pid = process_create(tdp_process, tdp_proc_name, 
                                 HUGE_STACK, PRIO_NORMAL);
    }
    */
}

void
topo_disc_uninit (void)
{   
    /* Uncomment this section when TDP proc is started.
    if (tdp_pid != NO_PROCESS) {
        process_kill(tdp_pid);
        tdp_pid = NO_PROCESS;
    }
    return;
    */
}
#endif
