/*
 * Copyright (c) 2014, 2015 Cisco Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.snbi.southplugin;


import java.net.InetAddress;
import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A SNBI node discovered through SNBI.
 */
public class SnbiNode {
    // The UDI of the node.
    private String udi = null;
    // The peer interface name.
    private String peerIfName = null;

    private InetAddress peerIfLLAddress = null;
    private InetAddress domainNodeIPaddr = null;

    // Logger.
    private static final Logger log = LoggerFactory.getLogger(SnbiNode.class);
    private SnbiRegistrar registrar = null;
    private SnbiNodeStateRegistrar registrarNode = null;
    private SnbiNodeStateNew newNode = null;
    private SnbiNodeStateInvite deviceInvite = null;
    private SnbiNodeStateBootStrap deviceBS = null;
    private SnbiNodeStateBootStrapReject deviceBsReject = null;
    private ISnbiNodeState currState = null;
    private X509Certificate cert = null;
    private boolean bootStrapped = false;
    private snbiNodeType nodeType;

    private String deviceID = null;
    enum snbiNodeType {
    	SNBI_NODE_TYPE_REGISTRAR,
    	SNBI_NODE_TYPE_FE
    }
    public static SnbiNode createNewNode (SnbiPkt pkt, SnbiRegistrar registrar) {
        SnbiNode node = new SnbiNode (snbiNodeType.SNBI_NODE_TYPE_FE, pkt, registrar);
        node.setState(SnbiNodeState.SNBI_NODE_STATE_NEW, null);
        return node;
    }

    public static SnbiNode createRegistrarNode (String UDI, SnbiRegistrar registrar) {
        SnbiNode node = new SnbiNode (snbiNodeType.SNBI_NODE_TYPE_REGISTRAR, UDI, registrar);
        node.setState(SnbiNodeState.SNBI_NODE_STATE_REGISTRAR, null);
        return node;
    }

    private SnbiNode (snbiNodeType nodeType, String udi, SnbiRegistrar registrar) {
    	this.nodeType = nodeType;
        this.udi = udi;
        this.registrar = registrar;
        instantiateNodeStates();
    }

    // timer.
    private SnbiNode (snbiNodeType nodeType, SnbiPkt pkt, SnbiRegistrar registrar) {
        String udi = pkt.getUDITLV();

        log.debug("[node:"+udi+"] New "+nodeType+" node created");
    	this.nodeType = nodeType;
        this.udi = udi;
        this.peerIfName = pkt.getIfNameTLV();
        this.registrar = registrar;
        this.peerIfLLAddress = pkt.getIPV6LLTLV();
        instantiateNodeStates();
    }
    
    public boolean nodeIsRegistrar() {
    	return (this.nodeType == snbiNodeType.SNBI_NODE_TYPE_REGISTRAR);
    }

    private void instantiateNodeStates() {
    	newNode = new SnbiNodeStateNew(this);
        deviceInvite = new SnbiNodeStateInvite(this);
        registrarNode = new SnbiNodeStateRegistrar(this);
        deviceBS = new SnbiNodeStateBootStrap(this);
        deviceBsReject = new SnbiNodeStateBootStrapReject(this);
    }

    /**
     * Get the UDI of the node.
     *
     * @return - The UDI string of the node.
     */
    public String getUDI() {
        return udi;
    }

    /**
     * Get peer IfName.
     */
    public String getPeerIfName () {
        return peerIfName;
    }

    public InetAddress getPeerIfLLAddress () {
        return peerIfLLAddress;
    }

    public InetAddress getNodeAddress () {
        return domainNodeIPaddr;
    }

    public SnbiRegistrar getRegistrar () {
        return registrar;
    }

    public void setNodeAddress (InetAddress addr) {
        domainNodeIPaddr = addr;
    }

    // State machine.
    private void setState(SnbiNodeState newState, eventContext evnt) {
        while (setNewState(newState)) {
            newState = currState.nodeStateSetEvent(evnt);
        }
    }

    private boolean setNewState (SnbiNodeState newState ) {
        log.debug("[node:"+this.getUDI()+"] CurrState "+
         (currState != null ? currState.getState():"NONE")+" NewState "+newState);

        if (currState != null && newState ==  SnbiNodeState.SNBI_NODE_STATE_NO_CHANGE) {
        	// Stop the state machine.
            return false;
        }

        switch (newState) {
            case SNBI_NODE_STATE_REGISTRAR:
                currState = registrarNode;
                break;
            case SNBI_NODE_BS_INVITE:
                currState = deviceInvite;
                break;
            case SNBI_NODE_STATE_BOOTSTRAP:
                currState = deviceBS;
                break;
            case SNBI_NODE_BS_REJECTED:
            	currState = deviceBsReject;
            	break;
            case SNBI_NODE_STATE_NEW:
            	currState = newNode;
            	break;
            default:
                log.error("Unhandled state "+newState);
                return false;
        }
        return true;
    }

    public SnbiNodeState getCurrState () {
        return currState.getState();
    }

    public void handleNodeCertReqPktEvent (SnbiPkt pkt) {
        setState(currState.handleNodeCertReqPktEvent(pkt), new eventContext(pkt));
    }

    public void handleNodeConnectPktEvent(SnbiPkt pkt) {
        setState(currState.handleNodeConnectPktEvent(pkt), new eventContext(pkt));
    }

    public void handleNodeBSReqPktEvent(SnbiPkt pkt) {
        setState(currState.handleNodeBSReqPktEvent(pkt), new eventContext(pkt));
    }

    public void setDeviceID(String deviceID) {
        this.deviceID = deviceID;
    }

    public String getDeviceID() {
        return deviceID;
    }

    public boolean isBootStrapped() {
        return this.bootStrapped;
    }

    public X509Certificate getCertificate() {
        return this.cert;
    }

    public void SetCertificate(X509Certificate cert) {
        this.cert = cert;
    }

    public void setBootStrapped(boolean b) {
        bootStrapped = b;
    }
}
