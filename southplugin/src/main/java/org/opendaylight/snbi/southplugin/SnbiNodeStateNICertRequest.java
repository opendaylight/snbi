package org.opendaylight.snbi.southplugin;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Timer;
import java.util.TimerTask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiNodeStateNICertRequest extends SnbiNodeStateCommonEventHandlers implements ISnbiNodeState {
    private static final Integer certReqRetryInterval = 40 * 1000; // 40 seconds Expiry
    private Timer certReqRetryTimer = null;
    private static final int maxRetryAttempt = 4;
    private int retryCount = 0;
    private static final Logger log = LoggerFactory.getLogger(SnbiNodeStateNICertRequest.class);



    public SnbiNodeStateNICertRequest(SnbiNode node) {
        super(node);
    }

    @Override
    public SnbiNodeState getState() {
        return SnbiNodeState.SNBI_NODE_STATE_NI_CERT_REQUEST;
    }

    @Override
    public SnbiNodeState nodeStateSetEvent(eventContext evt) {
        log.debug("[node:"+node.getUDI()+"] Set state : "+this.getState());
        startPeriodicNICertRequest(evt.getPkt().getSrcIP(), evt.getPkt().getIngressInterface());
        return node.getCurrState();
    }
    
    public SnbiNodeState handleNICertRspPktEvent (SnbiPkt pkt) {
        if (certReqRetryTimer != null) {
            certReqRetryTimer.cancel();
            certReqRetryTimer.purge();
            certReqRetryTimer = null;
        }
        return (super.handleNICertRspPktEvent(pkt));
    }
    
    private void startPeriodicNICertRequest (InetAddress dstIP, NetworkInterface intf) {
        //     TimerTask certReqRetryTimerTask = null;
 //       retryCount = 0;
 //       certReqRetryTimerTask = new TimerTask() {
 //           public void run() {
               sendNICertRequest(dstIP, intf);
 //           }
//        };

//        certReqRetryTimer = new Timer("Cert Req Periodic retry "
                //+ node.getUDI(), true);
        //certReqRetryTimer.schedule(certReqRetryTimerTask, 0, certReqRetryInterval);
    }
    
    private void sendNICertRequest(InetAddress dstIP, NetworkInterface intf) {

        SnbiPkt pkt = new SnbiPkt(SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP, 
                                  SnbiMsgType.SNBI_MSG_NI_CERT_REQ);
        pkt.setDstIP(dstIP);
        pkt.setUDITLV(node.getUDI());
        pkt.setEgressInterface(intf);
        SnbiMessagingInfra.getInstance().packetSend(pkt);
        
        retryCount++;
        if (retryCount >= maxRetryAttempt) {
            certReqRetryTimer.cancel();
            certReqRetryTimer.purge();
            certReqRetryTimer = null;
        }
    }
    
}
