package org.opendaylight.snbi.southplugin;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Timer;
import java.util.TimerTask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A SNBI node discovered through SNBI.
 */
public class SnbiNode {
    // Node Expiry timer, if no keep alive is received for 40 seconds, the node
    // is deemed lost.
    private Timer nodeExpiryTimer = null;
    // The UDI of the node.
    private String udi = null;
    // The peer interface name.
    private String peerIfName = null; 
    // The most recent Epoch time, when a refresh update was received.
    private InetAddress peerIfLLAddress = null;
    private InetAddress proxyAddress = null;
    private InetAddress domainNodeIPaddr = null;

    private long lastUpdateEpochTime;
    // Logger.
    private static final Logger log = LoggerFactory.getLogger(SnbiNode.class);
    // The expiry time period.
    private static final Integer ndExpiryTime = 40 * 1000; // 40 seconds Expiry
    private SnbiRegistrar registrar = null;
    // The periodic hello timer period.
    private static final Integer ndProbePeriod = 10 * 1000; // 10 seconds
    // The periodic hello timer.
    private Timer ndProbeTimer = null;
    private SnbiMessagingInfra msgInstance = null;
    private SnbiNodeStateNewNbr newNbrNode = null;
    private SnbiNodeStateNbrLost lostNbrNode = null;
    private SnbiNodeStateRegistrar registrarNode = null;
    private SnbiNodeStateNICertRequest niCertRequest = null;
    private SnbiNodeStateInvite deviceInvite = null;
    private ISnbiNodeState currState = null;
    private X509Certificate cert = null;
    private boolean bootStrapped = false;

    private String deviceID = null;
    
    public static SnbiNode createNeighborNode (SnbiPkt pkt, SnbiRegistrar registrar) {
        SnbiNode node = new SnbiNode (pkt, registrar);
        node.setState(SnbiNodeState.SNBI_NODE_STATE_NEW_NBR);
        return node;
    }
    
    public static SnbiNode createBootStrapNode (SnbiPkt pkt, SnbiRegistrar registrar) {
        SnbiNode node = new SnbiNode (pkt, registrar);
        return node;
    }
    
    public static SnbiNode createRegistrarNode (String UDI, SnbiRegistrar registrar) {
        SnbiNode node = new SnbiNode (UDI, registrar);
        node.setState(SnbiNodeState.SNBI_NODE_STATE_REGISTRAR);
        return node;
    }
    
    private SnbiNode (String udi, SnbiRegistrar registrar) {
        this.udi = udi;
        this.registrar = registrar;
        this.msgInstance = SnbiMessagingInfra.getInstance();
        instantiateNodeStates();
    }

    // timer.   
    private SnbiNode (SnbiPkt pkt, SnbiRegistrar registrar) {
        lastUpdateEpochTime = System.currentTimeMillis() / 1000L;
        String udi = pkt.getStringTLV(SnbiTLVType.SNBI_TLV_TYPE_UDI.getValue(),
                SnbiTLVSubtypeUDI.SNBI_TLV_STYPE_UDI.getValue());
        log.debug("[node: "+udi+"] New node created");
        this.udi = udi;
        this.peerIfName = pkt.getStringTLV(SnbiTLVType.SNBI_TLV_TYPE_IF_NAME.getValue(), 
                SnbiTLVSubtypeIfName.SNBI_TLV_STYPE_IF_NAME.getValue());
        this.registrar = registrar;
        this.peerIfLLAddress = pkt.getIPV6LLTLV();
        this.msgInstance = SnbiMessagingInfra.getInstance();

        instantiateNodeStates();

    }
    
    private void instantiateNodeStates() {
        newNbrNode = new SnbiNodeStateNewNbr(this);
        deviceInvite = new SnbiNodeStateInvite(this);
        lostNbrNode = new SnbiNodeStateNbrLost(this);
        registrarNode = new SnbiNodeStateRegistrar(this);
        niCertRequest = new SnbiNodeStateNICertRequest(this);
    }

    /**
     * Start the Neighbour Discovery process.
     */
    public void ndStart() {
        TimerTask ndProbeTimerTask = null;

        if (ndProbeTimer != null) {
            log.error("Timer already running Stop first");
            return;
        }
        
        // Create a new timer task.
        ndProbeTimerTask = new TimerTask() {
            public void run() {
                handleNDProbeTimerExpiredEvent();
            }
        };

        ndProbeTimer = new Timer("ND Periodic Probe "
                + registrar.getDomainName(), true);
        ndProbeTimer.schedule(ndProbeTimerTask, ndProbePeriod, ndProbePeriod);
        log.debug("Start ND timer");
    }

    /**
     * Send periodic ND packets on all interfaces.
     */
    private void sendPeriodicNDProbePacketsOnAllInterfaces() {
        try {
            Enumeration<NetworkInterface> intflist = NetworkInterface
                    .getNetworkInterfaces();
            while (intflist.hasMoreElements()) {
                NetworkInterface intf = intflist.nextElement();
                if (intf.isUp()) {
                    sendPeriodicNDPackets(intf);
                }
            }
        } catch (SocketException excpt) {
            log.error("Failed to send periodic ND packets" + excpt);
        } catch (IOException excpt) {
            log.error("Failed to send periodicND Hello packets" + excpt);
        }
    }

    /**
     * Send periodic ND packets on an interface.
     *
     * @param intf
     *            - The interface on which the ND packets has to be sent on.
     * @throws SocketException
     * @throws IOException
     */
    private void sendPeriodicNDPackets(NetworkInterface intf)
            throws SocketException, IOException {
//        log.debug("Send periodic Hello on interface "+intf.getDisplayName());
        // Create a new Message Type.
        SnbiPkt pkt = new SnbiPkt(
                SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY,
                SnbiMsgType.SNBI_MSG_ND_HELLO);
        
        pkt.setStringTLV(SnbiTLVType.SNBI_TLV_TYPE_UDI.getValue(),
                SnbiTLVSubtypeUDI.SNBI_TLV_STYPE_UDI.getValue(), 
                registrar.getNodeself().getUDI());
        
        pkt.setIPV6LLTLV(intf);
        pkt.setIfNameTLV(intf);
        pkt.setEgressInterface(intf);
        pkt.setDstIP(InetAddress.getByName("FF02::1"));
        
        msgInstance.packetSend(pkt);
    }
    

    // timer.

    /**
     * Start an Expiry Timer, if a timer already exists, then cancel/purge that
     * because we have received an update for this neighbor.
     */
    public void startNewExpiryTimer() {
        if (nodeExpiryTimer != null) {
            // We have received an update, so cancel the old timer.
            nodeExpiryTimer.cancel();
            nodeExpiryTimer.purge();
        }
        
        log.debug("[node: "+udi+"]Starting new timer for udi ");
        lastUpdateEpochTime = System.currentTimeMillis() / 1000L;
        nodeExpiryTimer = new Timer("Neighbor Node Expiry Timer "
                + this.udi, true);
        nodeExpiryTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                handleKeepAliveTimerExpiredEvent();
            }

        }, ndExpiryTime, ndExpiryTime);
    }
    
    public void reStartExpiryTimer() {
        startNewExpiryTimer();
    }
    /**
     * Stop the Neighbour Discovery process.
     */
    public void ndStop() {
        if (ndProbeTimer != null) {
            ndProbeTimer.cancel();
            ndProbeTimer.purge();
            ndProbeTimer = null;
        }
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
    
    public void setProxyIPAddress (InetAddress addr) {
        this.proxyAddress = addr;
    }
    public InetAddress getProxyIPAddress () {
        return proxyAddress;
    }
    public SnbiRegistrar getRegistrar () {
        return registrar;
    }
    
    public void setNodeAddress (InetAddress addr) {
        domainNodeIPaddr = addr;
    }

    protected void finalize() {
        if (nodeExpiryTimer != null) {
            nodeExpiryTimer.cancel();
            nodeExpiryTimer.purge();
        }
    }
    
    // State machine.
    private void setState(SnbiNodeState newState) {        
        while (setNewState(newState)) {
            newState = currState.nodeStateSetEvent();
        }
    }
    
    private boolean setNewState (SnbiNodeState newState ) {
        log.debug("[node:"+this.getUDI()+"] CurrState "+
         (currState != null ? currState.getState():"NONE")+" NewState "+newState);

        if (currState != null && currState.getState() == newState) {
            return false;
        }

        switch (newState) {
            case SNBI_NODE_STATE_NEW_NBR:
                currState = newNbrNode;
                break;
            case SNBI_NODE_STATE_NBR_LOST:
                currState = lostNbrNode;
                break;
            case SNBI_NODE_STATE_REGISTRAR:
                currState = registrarNode;
                break;
            case SNBI_NODE_STATE_NI_CERT_REQUEST:
                currState = niCertRequest;
                break;
            case SNBI_NODE_BS_INVITE:
                currState = deviceInvite;
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
    
    // Event Handlers.
    private void handleKeepAliveTimerExpiredEvent() {       
        setState(currState.handleNodeExpiredEvent());
    }
    
    public void handleNICertReqPktEvent (SnbiPkt pkt) {
        setState(currState.handleNICertReqPktEvent(pkt));
    }

    private void handleNDProbeTimerExpiredEvent () {
        sendPeriodicNDProbePacketsOnAllInterfaces();
    }

    /**
     * Received a new hello packet, restart the Expiry timer.
     *
     * @param pkt
     */
    public void handleNDRefreshPktEvent(SnbiPkt pkt) {
        setState(currState.handleNDRefreshPktEvent(pkt));
    }

    public void handleNICertRespPktEvent(SnbiPkt pkt) {
        setState(currState.handleNICertRspPktEvent(pkt));
    }

    public void handleNbrConnectPktEvent(SnbiPkt pkt) {
        setState(currState.handleNbrConnectPktEvent(pkt));
    }

    public void handleBSReqPktEvent(SnbiPkt pkt) {
        setState(currState.handleBSReqPktEvent(pkt));        
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