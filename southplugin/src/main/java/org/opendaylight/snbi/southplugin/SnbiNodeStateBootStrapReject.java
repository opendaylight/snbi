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

public class SnbiNodeStateBootStrapReject extends SnbiNodeStateCommonEventHandlers implements ISnbiNodeState {
    private static final Logger log = LoggerFactory.getLogger(SnbiNodeStateBootStrapReject.class);

    public SnbiNodeStateBootStrapReject(SnbiNode node) {
        super(node);
    }

    @Override
    public SnbiNodeState getState() {
        return SnbiNodeState.SNBI_NODE_BS_REJECTED;
    }

    @Override
    public SnbiNodeState nodeStateSetEvent(eventContext evnt) {
        log.debug("[node:"+node.getUDI()+"] Set state : "+this.getState());
        sendNodeRejectMsg(evnt.getPkt().getSrcIP(), evnt.getPkt().getIngressInterface());
        return SnbiNodeState.SNBI_NODE_STATE_NO_CHANGE;
    }

    private void sendNodeRejectMsg (InetAddress dstIP, NetworkInterface egressIntf) {
        SnbiPkt pkt = new SnbiPkt (SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP,
                SnbiMsgType.SNBI_MSG_NODE_BS_REJECT);
        pkt.setUDITLV(node.getUDI());
        pkt.setDstIP(dstIP);
        pkt.setEgressInterface(egressIntf);
        pkt.setSrcIP(node.getRegistrar().getNodeself().getNodeAddress());
        pkt.setRegistrarIPaddrTLV(node.getRegistrar().getNodeself().getNodeAddress());
        SnbiMessagingInfra.getInstance().packetSend(pkt);
    }


}
