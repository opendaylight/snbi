package org.opendaylight.controller.snbi.internal;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.concurrent.ConcurrentHashMap;
import java.net.DatagramPacket;
import java.net.Inet6Address;
import java.net.SocketException;
import java.net.MulticastSocket;
import java.net.NetworkInterface;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Messaging Infra, takes care of creating the required data bus of the
 * desired type.
 */
public class SnbiMessagingInfra {
    // The TTL for the multicast message.
    private static final byte mcastTTL = 1;
    // The source and destination port for SNBI.
    private final Integer snbiPortNumber = 8888;
    // Max UDP payload
    private final int MAX_UDP_PAYLOAD = 65535;
    // The multicast socket created during first time instantiation.
    private MulticastSocket mcastSocket = null;
    // Multicast Thread
    private Thread mThread = null;
    // Multicast Thread Terminate
    private boolean mThreadrun = true;
    // The multicast group that SNBI messages are sent.
    private final String mcastIPString = "FF02::1";
    // The singleton instance.
    private static SnbiMessagingInfra snbiMsgInfraInstance = null;
    // The multicast InetAddress for the mcast IP string.
    private InetAddress mcastIP = InetAddress.getByName(mcastIPString);
    // The logger object.
    private static final Logger log = LoggerFactory
            .getLogger(SnbiMessagingInfra.class);
    // List of pkt listeners.
    private ConcurrentHashMap<Integer, SnbiMsgInfraIncomingPktListener> rcvPktListenerList = null;

    /**
     * Get the Singleton instance of the messaging infrastructure.
     *
     * @return The singleton instance.
     */
    public static SnbiMessagingInfra getInstance() {
        try {
            synchronized (SnbiMessagingInfra.class) {
                if (snbiMsgInfraInstance == null) {
                    snbiMsgInfraInstance = new SnbiMessagingInfra();
                }
            }
        } catch (Exception excpt) {
            return null;
        }
        return (snbiMsgInfraInstance);
    }

    /**
     * Register a given listener.
     *
     * @return - The handle, which can be used for unregistration as well. The
     *         listener is registered only once, multiple registration will just
     *         ignore the new registration.
     */
    public int registerRcvPktListener(
            SnbiMsgInfraIncomingPktListener rcvPktListener) {
        if (rcvPktListenerList == null) {
            log.debug("Create New Pkt Listener");

            rcvPktListenerList = new ConcurrentHashMap<Integer, SnbiMsgInfraIncomingPktListener>();
        }

        if (rcvPktListenerList.get(rcvPktListener.hashCode()) == null) {
            log.debug("New listener ADD.");
            rcvPktListenerList.put(rcvPktListener.hashCode(), rcvPktListener);
        }
        log.debug("Listener registration success");
        return rcvPktListener.hashCode();
    }

    /**
     * Unregister the listener.
     *
     * @param rcvPktListenerHandle
     *            - The handle that was returned as part of the registration.
     */
    public void unregisterRcvPktListener(int rcvPktListenerHandle) {
        rcvPktListenerList.remove(rcvPktListenerHandle);
    }

    /**
     * Set up the required message sockets.
     *
     * @throws Exception
     *             - Throws generic exception if failed to init the sockets.
     */
    private SnbiMessagingInfra() throws Exception {
        log.debug("Initing SnbiMessagingInfra");
        try {
            // Init the various modules.
            snbiMulticastSocketInit();
        } catch (Exception excpt) {
            log.error("Failed to Init SnbiMessagingInfra");
            throw excpt;
        }
        log.debug("SnbiMessagingInfra Sucess");
    }

    /**
     * Setup a multicast socket, bind it to a port and join the multicast group.
     *
     * @throws IOException
     *             - Throws IOException if creating a socket failed.
     */
    private void snbiMulticastSocketInit() throws IOException {
        log.debug("Initing SnbiMulticastSocket");
        try {
            mcastSocket = new MulticastSocket(snbiPortNumber);
            mcastSocket.joinGroup(mcastIP);
            // Nonintutive, set to TRUE not to loopback.
            mcastSocket.setLoopbackMode(true);
            // The number of hops the packets can propagate.
            mcastSocket.setTimeToLive(mcastTTL);

            // Creating an anonymous thread.
            mThread = new Thread("Mcast Listener Thread") {
                public void run() {
                    // Call a routine to listen to multicast packets.
                    mcastPktReceiver();
                }
            };
            log.debug("Mcast listener thread started");
            this.mThreadrun = true;
            mThread.start();
        } catch (IOException excpt) {
            log.error("Unable to obtain Socket " + excpt);
        }
    }

    /**
     * This is a multicast packet receiver routine, the thread run in the
     * background listening to all multicast packet of a group.
     */
    private void mcastPktReceiver() {
        byte[] mcastBuffer = new byte[MAX_UDP_PAYLOAD];
        DatagramPacket mcastPacket;
        InetAddress fromIP;
        Inet6Address ipv6addr;
        int scopeID = 0;

        NetworkInterface intf;
        mcastPacket = new DatagramPacket(mcastBuffer, mcastBuffer.length);
        log.info("Mcast pkt receiver");

        while (mThreadrun) {
            try {
                mcastSocket.receive(mcastPacket);
                // Create a new pkt instance from the message byte stream.
                SnbiPkt pkt = new SnbiPkt(mcastPacket.getData(),
                        mcastPacket.getLength());
                fromIP = mcastPacket.getAddress();
                ipv6addr = (Inet6Address) fromIP;
                scopeID = ipv6addr.getScopeId();
                intf = NetworkInterface.getByIndex(scopeID);
                pkt.setInterface(intf);
                log.debug("Received packet from " + intf.getDisplayName());
                // Notify all relevant listeners about the received packet.
                notifyIncomingPacket(pkt);
            } catch (IOException excpt) {
                log.error("Exception in receive mcast packet " + excpt);
            } catch (NullPointerException excpt) {
                log.error("Null pointer exception failed to fetch interface for index "
                        + scopeID);
            }
        }
    }

    /**
     * Notify all relevant listeners about the received packet. The notification
     * to each client is filtered
     *
     * @param pkt
     *            -
     */
    private void notifyIncomingPacket(SnbiPkt pkt) {
        SnbiMsgInfraIncomingPktListener rcvpktlistener = null;
        SnbiMsgInfraFilter filter = null;
        IsnbiMessagingInfra iListener = null;

        if (rcvPktListenerList == null) {
            return;
        }
        for (ConcurrentHashMap.Entry<Integer, SnbiMsgInfraIncomingPktListener> entry : rcvPktListenerList
                .entrySet()) {
            rcvpktlistener = entry.getValue();
            filter = rcvpktlistener.getFilter();
            iListener = rcvpktlistener.getListener();
            log.debug("Sending listener notification to ==> "
                    + rcvpktlistener.getString());
            if (filter.matchPkt(pkt)) {
                iListener.rcvPktListenerCb(pkt);
            }
        }
    }

    /**
     * Send a multicast packet on a given interface identified by the index.
     *
     * @param pkt
     *            - The packet that needs to be send, all necessary TLVs should
     *            be associated with the packet.
     * @param intfIndex
     *            - The index of the interface on which the packet should be
     *            sent out on.
     * @throws SocketException
     * @throws IOException
     */
    public void sendMulticastPacket(SnbiPkt pkt, NetworkInterface intf)
            throws SocketException, IOException {
        DatagramPacket mcastPacket = null;

        try {
            Enumeration<InetAddress> inetAddresses = intf.getInetAddresses();
            for (InetAddress inetAddress : Collections.list(inetAddresses)) {
                if (inetAddress.isLinkLocalAddress()) {
                    log.debug("Multicast pkt send Setting interface "
                            + inetAddress);
                    mcastSocket.setInterface(inetAddress);
                }
            }
            // Create a multicast datagram and send it out.
            mcastPacket = new DatagramPacket(pkt.getMsg(), pkt.getMsgLength(),
                    mcastIP, snbiPortNumber);
            mcastSocket.send(mcastPacket);
        } catch (SocketException excpt) {
            log.error("Failed to send multicast packet via interface "
                    + intf.getDisplayName() + excpt);
            throw excpt;
        } catch (IOException excpt) {
            log.error("Failed to send multicast packet via intfIndex "
                    + intf.getDisplayName() + " " + excpt);
            throw excpt;
        } catch (NullPointerException excpt) {
            log.error("Encountered a NULL pointer exception" + excpt);
            excpt.printStackTrace();
        }
    }

    protected void finalize () {
        if (mcastSocket != null) {
            mcastSocket.disconnect();
            mcastSocket.close();
            mcastSocket = null;
        }

        if (mThread != null) {
            this.mThreadrun = false;
            try {
                mThread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

    }
}

/**
 * Interface for the messaging service.
 */
interface IsnbiMessagingInfra {
    /*
     * The callback for receiving received packets that match the registered
     * filter.
     */
    void rcvPktListenerCb(SnbiPkt pkt);

}

/**
 * The Listener Infra for receiving packets that match a certain filter
 * criteria.
 *
 */
class SnbiMsgInfraIncomingPktListener {
    private SnbiMsgInfraFilter filter;
    private IsnbiMessagingInfra listener;
    private String clientString = null;
    private static final Logger log = LoggerFactory
            .getLogger(SnbiMsgInfraIncomingPktListener.class);

    /**
     * Create the Listener with the given criteria.
     *
     * @param filter
     *            - The filter that should be matched.
     * @param listener
     *            - The object which should invoked upon a match.
     * @param clientString
     *            - The client String for debugging.
     */
    public SnbiMsgInfraIncomingPktListener(SnbiMsgInfraFilter filter,
            IsnbiMessagingInfra listener, String clientString) {
        this.clientString = clientString;
        this.filter = filter;
        this.listener = listener;
    }

    public String getString() {
        return (clientString);
    }

    /**
     * Get the filter that is associated with this listener.
     *
     * @return - The message filter that is associated with this listener.
     */
    public SnbiMsgInfraFilter getFilter() {
        return filter;
    }

    /**
     * Get the registered callback object associated with this listener.
     *
     * @return - The listener interface that is associated with this listener.
     */
    public IsnbiMessagingInfra getListener() {
        return listener;
    }
}

/**
 * The clients can install listners and listen to only certain packets.
 */

class SnbiMsgInfraFilter {
    // Based on domain Name.
    private String domainName = null;
    // Message Type Filter array.
    private ArrayList<SnbiMsgType> msgTypeFilterList = null;
    // Protocol Type filter array.
    private ArrayList<SnbiProtocolType> protocolTypeFilterList = null;
    // Logger object.
    private static final Logger log = LoggerFactory
            .getLogger(SnbiMsgInfraFilter.class);

    /**
     * @param clientString
     *            - The client string.
     */
    public SnbiMsgInfraFilter() {
    }

    /**
     * Set the domain name filter.
     *
     * @param domainName
     *            - Traffic particular to a Domain Name.
     */
    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    /**
     * Get the domain Name.
     *
     * @return - The domain Name of the filter.
     */
    public String getDomainName() {
        return domainName;
    }

    /**
     * Set Of messages that the client is interested in.
     *
     * @param msgTypeFilter
     *            - The collection of Message Types of Interest.
     */
    public void setMsgTypeFilter(Collection<SnbiMsgType> msgTypeFilter) {
        this.msgTypeFilterList = new ArrayList<SnbiMsgType>(
                msgTypeFilter.size());
        for (SnbiMsgType msgType : msgTypeFilter) {
            this.msgTypeFilterList.add(msgType);
        }
    }

    /**
     * Set of Protocol Types the clients in interested in. Multiple sets will
     * replace the old one.
     *
     * @param protocolTypeFilter
     *            - The collection of ProtocolTypes of interest.
     */
    public void setProtocolTypeFilter(
            Collection<SnbiProtocolType> protocolTypeFilter) {
        this.protocolTypeFilterList = new ArrayList<SnbiProtocolType>(
                protocolTypeFilter.size());
        for (SnbiProtocolType protocolType : protocolTypeFilter) {
            this.protocolTypeFilterList.add(protocolType);
        }
    }

    /**
     * Match the protocol type to the registered set of the protocol types.
     *
     * @param protocolType
     *            - The protocol Type that should be matched.
     * @return true - If the list is empty i,e no protocol type criteria has
     *         been set or if the protocol type matched the given protocolType.
     *         false - otherwise
     */
    public boolean matchProtocolType(SnbiProtocolType protocolType) {
        if (protocolTypeFilterList == null) {
            log.debug("Match protocol Type null list");
            return true;
        }
        for (SnbiProtocolType protoType : this.protocolTypeFilterList) {
            // Its ok to compare the enums directly rather than using the values
            // themselves.
            if (protoType == protocolType) {
                log.debug(":Match protocol Type found a match in list");
                return true;
            }
        }
        log.debug("No Match protocol Type found a match in list");
        return false;
    }

    /**
     * Match the Message type to the registered set of the protocol types.
     *
     * @param msgType
     *            - The protocol Type that should be matched.
     * @return true - If the list is empty i,e no protocol type criteria has
     *         been set or if the protocol type matched the given protocolType.
     *         false - otherwise.
     */
    public boolean matchMsgType(SnbiMsgType msgType) {
        if (msgTypeFilterList == null) {
            log.debug("Match Msg Type null list");
            return true;
        }
        for (SnbiMsgType mtype : msgTypeFilterList) {
            // Its ok to compare the enums directly rather than using the values
            // themselves.
            if (mtype == msgType) {
                log.debug("Match Msg Type found a match in list");
                return true;
            }
        }
        log.debug("No Match Msg Type found a match in list");
        return false;
    }

    /**
     * Match the domain Name registered.
     *
     * @param domainName
     *            - The domainName in the incoming packet.
     * @return true - If the domain Names matched, false - otherwise.
     */
    public boolean matchDomainName(String domainName) {
        boolean match;
        if (this.domainName == null) {
            log.debug("DomainName string Null string");
            return true;
        }
        match = this.domainName.equals(domainName);
        log.debug("DomainName string match " + match);
        return match;
    }

    /**
     * Given a packet, check if it matches any critera.
     *
     * @param pkt
     *            - The packet that has to matched.
     * @return - True, if any of the filter criteria was met.
     */
    public boolean matchPkt(SnbiPkt pkt) {
        // For now we are interested in protocol type based match.
        if (matchProtocolType(pkt.getProtocolType())) {
            return true;
        }
        return false;
    }
}
