/*
 * Copyright (c) 2014, 2015 Cisco Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.snbi.southplugin;

import java.net.InetAddress;
import java.net.NetworkInterface;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiNodeStateBootStrap extends SnbiNodeStateCommonEventHandlers implements ISnbiNodeState {

    private static Logger log = LoggerFactory.getLogger(SnbiNodeStateBootStrap.class);

    public SnbiNodeStateBootStrap(SnbiNode node) {
        super(node);
    }

    @Override
    public SnbiNodeState getState() {
        return SnbiNodeState.SNBI_NODE_STATE_BOOTSTRAP;
    }

    @Override
    public SnbiNodeState nodeStateSetEvent(eventContext evnt) {
        sendBSRespMsg(evnt.getPkt().getSrcIP(), evnt.getPkt().getIngressInterface());
        return node.getCurrState();
    }

    private void sendBSRespMsg (InetAddress dstIP, NetworkInterface egressIntf) {
        SnbiPkt pkt = new SnbiPkt (SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP, SnbiMsgType.SNBI_MSG_BS_RESP);
        pkt.setDstIP(dstIP);
        pkt.setUDITLV(node.getUDI());
        pkt.setEgressInterface(egressIntf);
        if (node.isBootStrapped()) {
            pkt.setDomainCertTLV(node.getCertificate());
        }
        SnbiMessagingInfra.getInstance().packetSend(pkt);
    }

}
