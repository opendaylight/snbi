package org.opendaylight.snbi.southplugin;

import java.net.InetAddress;
import java.net.NetworkInterface;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiNodeStateInvite extends SnbiNodeStateCommonEventHandlers implements ISnbiNodeState {
    private static final Logger log = LoggerFactory.getLogger(SnbiNodeStateInvite.class);
    
    public SnbiNodeStateInvite(SnbiNode node) {
        super(node);
    }

    @Override
    public SnbiNodeState getState() {
        return SnbiNodeState.SNBI_NODE_BS_INVITE;
    }

    @Override
    public SnbiNodeState nodeStateSetEvent(eventContext evnt) {
        log.debug("[node: "+node.getUDI()+"] Set state : "+this.getState());
        sendNodeInviteMsg(evnt.getPkt().getSrcIP(), evnt.getPkt().getIngressInterface());        
        return node.getCurrState();
    }
    
    private boolean validateNodeForInvite() {
        if (node.getUDI() == null) {
            log.error("Validate Node for Invite failed with null UDI");
            return false;
        }
        
        if (node.getRegistrar() == null || node.getRegistrar().getNodeself() == null ||
                node.getRegistrar().getNodeself().getNodeAddress() == null) {
            log.error("[node: "+node.getUDI()+"] Validate Node for Invite failed with Null registrar address");
            return false;
        }        
        if (node.getDeviceID() == null) {
            log.error("[node: "+node.getUDI()+"] Validate Node for Invite failed with Null device ID");
            return false;
        }
        if (node.getRegistrar().getDomainName() == null) {
            log.error("[node: "+node.getUDI()+"] Validate Node for Invite failed with Null domain Name");
            return false;
        }
        if (CertManager.getInstance().getRootCACertificate() == null) {
            log.error("[node: "+node.getUDI()+"] Validate Node for Invite failed with Null CA certificate");
            return false;
        }   
        return true;
    }

    private boolean sendNodeInviteMsg(InetAddress dstIP, NetworkInterface egressIntf) {
        
        if (!validateNodeForInvite()) {
            return false;
        }
        
        SnbiPkt pkt = new SnbiPkt (SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP, 
                                   SnbiMsgType.SNBI_MSG_BS_INVITE);

        pkt.setUDITLV(node.getUDI());
        pkt.setDstIP(dstIP);
        pkt.setEgressInterface(egressIntf);
        pkt.setSrcIP(node.getRegistrar().getNodeself().getNodeAddress());
        pkt.setDeviceIDTLV(node.getDeviceID());
        pkt.setRegistrarIDTLV(node.getRegistrar().getRegistrarID());
        pkt.setDomainIDTLV(node.getRegistrar().getDomainName());
        pkt.setRegistrarIPaddrTLV(node.getRegistrar().getNodeself().getNodeAddress());
        pkt.setCACertTLV(CertManager.getInstance().getRootCACertificate());

        if (node.getRegistrar().getNodeself().isBootStrapped()) {
            pkt.setRegistrarCertTLV(node.getRegistrar().getNodeself().getCertificate());
            // add RA signature.
        }
        SnbiMessagingInfra.getInstance().packetSend(pkt);

        return true;
    }
}
