package org.opendaylight.snbi.southplugin;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class SnbiNodeStateCommonEventHandlers implements ISnbiNodeState {
    protected SnbiNode node = null;
    private static final Logger log = LoggerFactory.getLogger(SnbiNodeStateCommonEventHandlers.class);

    
    public SnbiNodeStateCommonEventHandlers (SnbiNode node) {
        this.node = node;
    }
    
    public SnbiNodeState handleNDRefreshPktEvent (SnbiPkt pkt) {
        log.debug("[node: "+node.getUDI()+"]Handle ND refresh Pkt Event: "+pkt.getUDITLV());
        node.reStartExpiryTimer();
        // No state change.
        return node.getCurrState();
    }
    
    public SnbiNodeState handleNodeExpiredEvent () {
        log.debug("[node: "+node.getUDI()+"] Handle Node Expired Event : "+node.getUDI());
        return node.getCurrState();
    }
    
    public SnbiNodeState handleNICertReqPktEvent (SnbiPkt pkt) {
        log.debug("[node: "+node.getUDI()+"] Handle NI Cert Req pkt event: "+pkt.getUDITLV());
        sendNodeCertResponseMsg(pkt.getSrcIP());
        return node.getCurrState();
    }
    
    private void sendNodeCertResponseMsg (InetAddress dstIP) {
        SnbiPkt pkt = new SnbiPkt (SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP, SnbiMsgType.SNBI_MSG_NI_CERT_RESP);
        pkt.setUDITLV(node.getRegistrar().getNodeself().getUDI());
        pkt.setDstIP(dstIP);
        pkt.setSrcIP(node.getRegistrar().getNodeself().getNodeAddress());
        
        if (node.getRegistrar().getNodeself().isBootStrapped()) {
            pkt.setDomainCert(node.getRegistrar().getNodeself().getCertificate());
        }
        SnbiMessagingInfra.getInstance().packetSend(pkt);
    }
    
    public SnbiNodeState handleNICertRspPktEvent (SnbiPkt pkt) {
        log.debug("[node: "+node.getUDI()+"] Handle NI Cert Resp Pkt Event: "+pkt.getUDITLV());
        return node.getCurrState();
    }
    
    public SnbiNodeState handleNbrConnectPktEvent (SnbiPkt pkt) {
        log.debug("[node: "+node.getUDI()+"] Handle Nbr Conneck pkt Event: "+pkt.getUDITLV());
        return node.getCurrState();
    }
    
    public SnbiNodeState handleBSReqPktEvent (SnbiPkt pkt) {
        log.debug("[node: "+node.getUDI()+"] Handle BSReq Pkt Event: "+pkt.getUDITLV());
        if (node.getRegistrar().validateNode(node)) {
            
        }
        return node.getCurrState();
    }
    
    public SnbiNodeState handleBSInvitePktEvent (SnbiPkt pkt) {
        log.debug("[node: "+node.getUDI()+"] Handle BSInvite Pkt Event: "+pkt.getUDITLV());
        return node.getCurrState();

    }
}
