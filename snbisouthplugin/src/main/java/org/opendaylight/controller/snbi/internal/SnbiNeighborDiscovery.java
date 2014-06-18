package org.opendaylight.controller.snbi.internal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opendaylight.controller.snbi.Snbi;

import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Collections;
import java.util.Enumeration;
import java.util.concurrent.ConcurrentHashMap;
import java.net.SocketException;
import java.net.NetworkInterface;

/**
 * Neighbour Discovery module. Performs neighbour discovery for a given domain.
 */
public class SnbiNeighborDiscovery implements IsnbiMessagingInfra, ISnbiNode {
    // The handler returned after listener registration.
    int rcvPktListenerHandle = 0;
    // The periodic hello timer.
    private Timer ndHelloTimer = null;
    // The Snbi instance that is associated with the ND.
    private Snbi snbiInstance = null;
    // The message infrastructure instance.
    private SnbiMessagingInfra msgInfraInstance = null;
    // The periodic hello timer period.
    private static final Integer ndHelloPeriod = 10 * 1000; // 10 seconds
    // refresh timer.
    // Logger.
    private static final Logger log = LoggerFactory
            .getLogger(SnbiNeighborDiscovery.class);
    // UDI for this box, for now hardcoded, but need to figure out some way.
    private final String myUdiString = "PID:JAVA-CONTROLLER SN:1234";
    // The list of Nodes discovered.
    ConcurrentHashMap<String, SnbiNode> NeighborHashList = null;

    /**
     * Instantiate Neighbour discovery for a give SNBI instance.
     *
     * @param snbiInstance
     *            - The Snbi Instance corresponding to which neighbor discovery
     *            is performed.
     */
    public SnbiNeighborDiscovery(Snbi snbiInstance) {

        try {
            this.snbiInstance = snbiInstance;
            this.msgInfraInstance = SnbiMessagingInfra.getInstance();
            NeighborHashList = new ConcurrentHashMap<String, SnbiNode>();
        } catch (Exception excpt) {
            log.error("Failed to Obtain MessagingInfra instance");
        }
    }

    /**
     * Get the list of neighbour nodes for a domain.
     *
     * @return - List of Neighbor Nodes.
     */
    public List<SnbiNode> getNeighborNodes() {
        return new ArrayList<SnbiNode>(NeighborHashList.values());
    }

    /**
     * Start the Neighbour Discovery process.
     */
    public void ndStart() {
        TimerTask ndHelloTimerTask = null;

        if (ndHelloTimer != null) {
            log.error("Timer already running Stop first");
            return;
        }

        // Create a new timer task.
        ndHelloTimerTask = new TimerTask() {
            public void run() {
                sendPeriodicNDPacketsOnAllInterfaces();
            }
        };

        ndHelloTimer = new Timer("ND Periodic Hello "
                + snbiInstance.getDomainName(), true);
        ndHelloTimer.schedule(ndHelloTimerTask, ndHelloPeriod, ndHelloPeriod);
        log.debug("Start ND timer");
        registerNDRcvHelloPackets();
    }

    /**
     * Send periodic ND packets on all interfaces.
     */
    private void sendPeriodicNDPacketsOnAllInterfaces() {
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
        // Create a new Message Type.
        SnbiPkt pkt = new SnbiPkt(
                SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY,
                SnbiMsgType.SNBI_MSG_ND_HELLO);
        NDaddUDITLV(pkt);
        NDaddIPV6TLV(intf, pkt);
        NDaddIfNameTLV(intf, pkt);
        msgInfraInstance.sendMulticastPacket(pkt, intf);
    }

    /**
     * Stop the Neighbour Discovery process.
     */
    public void ndStop() {
        if (ndHelloTimer != null) {
            ndHelloTimer.cancel();
            ndHelloTimer.purge();
            ndHelloTimer = null;
        }
        unregisterNDRcvHelloPackets();
        clearAllNeighborList();
    }

    private void clearAllNeighborList() {
        NeighborHashList.clear();
    }

    // Add UDI to the tlv list.
    private void NDaddUDITLV(SnbiPkt pkt) {
        pkt.addTLV(new TLV(SnbiTLVType.SNBI_TLV_TYPE_UDI.getValue(),
                SnbiTLVSubtypeUDI.SNBI_TLV_STYPE_UDI.getValue(), myUdiString
                        .getBytes(), myUdiString.length()));
    }

    // Add the link local address to the TLV list.
    private void NDaddIPV6TLV(NetworkInterface intf, SnbiPkt pkt) {
        Enumeration<InetAddress> inetAddresses = intf.getInetAddresses();
        for (InetAddress inetAddress : Collections.list(inetAddresses)) {
            if (inetAddress.isLinkLocalAddress()) {
                pkt.addTLV(new TLV(SnbiTLVType.SNBI_TLV_TYPE_IPADDR.getValue(),
                        SnbiTLVSubtypeIPaddr.SNBI_TLV_STYPE_IPV6_ADDR
                                .getValue(), inetAddress.getAddress(),
                        inetAddress.getAddress().length));
            }
        }
    }

    // Add the Interface name to the TLV list.
    private void NDaddIfNameTLV(NetworkInterface intf, SnbiPkt pkt) {
        pkt.addTLV(new TLV(SnbiTLVType.SNBI_TLV_TYPE_IFNAME.getValue(),
                SnbiTLVSubtypeIfName.SNBI_TLV_STYPE_IF_NAME.getValue(), intf
                        .getName().getBytes(), intf.getName().length()));
    }

    /**
     * Register to receive ND packets from the messaging infra.
     */
    private void registerNDRcvHelloPackets() {
        SnbiMsgInfraIncomingPktListener rcvPktListener = null;
        SnbiMsgInfraFilter filter = new SnbiMsgInfraFilter();
        filter.matchProtocolType(SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY);
        rcvPktListener = new SnbiMsgInfraIncomingPktListener(filter, this,
                "ND:" + snbiInstance.getDomainName());
        rcvPktListenerHandle = msgInfraInstance
                .registerRcvPktListener(rcvPktListener);
    }

    private void unregisterNDRcvHelloPackets() {
        if (rcvPktListenerHandle != 0)
            msgInfraInstance.unregisterRcvPktListener(rcvPktListenerHandle);
    }

    /**
     * Receive incoming hello packets.
     */
    @Override
    public void rcvPktListenerCb(SnbiPkt pkt) {
        try {
            String udi = pkt.getTLVString(
                    SnbiTLVType.SNBI_TLV_TYPE_UDI.getValue(),
                    SnbiTLVSubtypeUDI.SNBI_TLV_STYPE_UDI.getValue());
            log.debug("UDI received in Listener callback: " + udi);
            if (NeighborHashList.containsKey(udi) == false) {
                if (!udi.equals(myUdiString)) {
                    // New Neighbour detected and its not the same as my UDI,
                    // avoid loopback packets.
                    SnbiNode neighborNode = new SnbiNode(pkt);
                    NeighborHashList.put(udi, neighborNode);
                }
            } else {
                SnbiNode node = NeighborHashList.get(udi);
                node.handleHelloRefreshPacket(pkt);
            }
        } catch (NullPointerException excpt) {
            // unable to get the UDI ignore this message.
            log.error("Null pointer exception " + excpt);
        }
    }

    /**
     * Handle Node expired notification.
     */
    @Override
    public void nodeExpiredNotification(SnbiNode node) {
        if (NeighborHashList.containsKey(node.getUDI()) == false) {
            log.error("Received Expiry notification for a non existant node "
                    + node.getUDI());
        }
        NeighborHashList.remove(node.getUDI(), node);
    }

    protected void finalize() {
        ndStop();
    }
}
