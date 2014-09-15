package org.opendaylight.snbi.southplugin;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

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
    private MulticastSocket socket = null;
    // Multicast Thread
    private Thread pktRcvrThread = null; 
    // Multicast Thread Terminate
    private boolean pktRcvrThreadrun = true;
    
    
    private Thread pktRcvdNotifyThread = null;
    private boolean pktTcvdNotifyThreadrun = true;
    BlockingQueue<SnbiPkt> pktRcvdNotifyQueue = null;

    private Thread pktSenderThread = null;
    private boolean pktSenderThreadrun = true;
    BlockingQueue<SnbiPkt> pktSendQueue = null;

    // The singleton instance.
    private static SnbiMessagingInfra snbiMsgInfraInstance = null;
 
    // The logger object.
    private static final Logger log = LoggerFactory
            .getLogger(SnbiMessagingInfra.class);
    // List of pkt listeners.
    private ConcurrentHashMap<Integer,ISnbiMsgInfraPktsListener> rcvPktListenerList = null;
    

    /**
     * Get the Singleton instance of the messaging infrastructure.
     *
     * @return The singleton instance.
     */
    public static SnbiMessagingInfra getInstance() {
        try {
            synchronized (SnbiMessagingInfra.class) {
                if (snbiMsgInfraInstance == null) {
                    log.debug("Initializing Message Infra");
                    snbiMsgInfraInstance = new SnbiMessagingInfra();
                }
            }
        } catch (Exception excpt) {
            return null;
        }
        return (snbiMsgInfraInstance);
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
            pktNotifyThreadinit();
            pktRcvListenerInit();
            socketInit();
        } catch (Exception excpt) {
            log.error("Failed to Init SnbiMessagingInfra");
            excpt.printStackTrace();
            throw excpt;
        }
        log.debug("SnbiMessagingInfra Sucess");
    }
    
    private void pktRcvListenerInit () {
        rcvPktListenerList = new ConcurrentHashMap<Integer,ISnbiMsgInfraPktsListener> ();
    }
    
    private void pktNotifyThreadinit () {
        pktRcvdNotifyQueue = new LinkedBlockingQueue<SnbiPkt>();

        pktRcvdNotifyThread = new Thread ("Packet Notification Thread") {
            public void run () {
                pktNotifyListenerThread();
            }
        };
        
        pktRcvdNotifyThread.start();
    }
    
    private void pktNotifyListenerThread () {
        SnbiPkt pkt;
        while (pktTcvdNotifyThreadrun) {
            try {
                pkt = pktRcvdNotifyQueue.take();
                notifyIncomingPacket(pkt);
            } catch (InterruptedException e) {
                log.error("Interrupt error"+e);
            }
        }
    }
    
    private void pktSender () {
        SnbiPkt pkt = null;
        while (pktSenderThreadrun) {
            try {
                pkt = pktSendQueue.take();
                packetSendInternal(pkt);
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (SocketException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    
    /**
     * Setup a multicast socket, bind it to a port and join the multicast group.
     * @throws IOException
     *             - Throws IOException if creating a socket failed.
     */
    private void socketInit() throws IOException {
        log.debug("Initing SnbiMulticastSocket");
        socket = new MulticastSocket(snbiPortNumber);
        socket.setReuseAddress(true);
        socket.joinGroup(SnbiUtils.getIPv6MutlicastAddress());
        // Nonintutive, set to TRUE not to loopback.
        socket.setLoopbackMode(true);
        // The number of hops the packets can propagate.
        socket.setTimeToLive(mcastTTL);

        // Creating an anonymous thread.
        pktRcvrThread = new Thread("Pkt Listener Thread") {
            public void run() {
                // Call a routine to listen to packets.
                packetReceiver();
            }
        };
        
        log.debug("Mcast listener thread started");
        this.pktRcvrThreadrun = true;
        pktRcvrThread.start();
        
        pktSendQueue = new LinkedBlockingQueue<SnbiPkt>();
        pktSenderThread = new Thread ("Pkt sender thread") {
            public void run () {
                pktSender();
            }
        };
        pktSenderThreadrun = true;
        pktSenderThread.start();
    }

    /**
     * This is a multicast packet receiver routine, the thread run in the
     * background listening to all multicast packet of a group.
     */
    private void packetReceiver() {
        byte[] mcastBuffer = new byte[MAX_UDP_PAYLOAD];
        DatagramPacket mcastPacket;
        InetAddress fromIP;
        Inet6Address ipv6addr;
        int scopeID = 0;

        NetworkInterface intf;
        mcastPacket = new DatagramPacket(mcastBuffer, mcastBuffer.length);
        log.info("Mcast pkt receiver");

        while (pktRcvrThreadrun) {
            try {
                socket.receive(mcastPacket);
                // Create a new pkt instance from the message byte stream.
                SnbiPkt pkt = new SnbiPkt(mcastPacket.getData(),
                        mcastPacket.getLength());
                fromIP = mcastPacket.getAddress();
                ipv6addr = (Inet6Address) fromIP;
                scopeID = ipv6addr.getScopeId();
                intf = NetworkInterface.getByIndex(scopeID);
                pkt.setIngressInterface(intf);
                pkt.setSrcIP(fromIP);
                // Notify all relevant listeners about the received packet.
                pktRcvdNotifyQueue.put(pkt);
            } catch (IOException excpt) {
                log.error("Exception in receive mcast packet " + excpt);
            } catch (NullPointerException excpt) {
                log.error("Null pointer exception failed to fetch interface for index "
                        + scopeID);
            } catch (InterruptedException excpt) {
                log.error("Interrupt exception "+excpt);
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
        ISnbiMsgInfraPktsListener rcvpktlistener = null;

        if (rcvPktListenerList == null) {
            return;
        }
        
        log.debug("IN packet: Length:"+pkt.getMsgLength()+" UDI:"+pkt.getUDITLV()+"\n\t\t\tProtocol ID:"+pkt.getProtocolType()+
                " Msg ID:"+pkt.getmsgType()+"\n\t\t\tSRC IP:"+pkt.getSrcIP()+" DST IP:"
                +pkt.getDstIP()+"\n\t\t\tIngressIntf:"+pkt.getEgressInterface()+"\n\t\t\t"+getProtocolDebugMsg(pkt));
        for (ConcurrentHashMap.Entry<Integer, ISnbiMsgInfraPktsListener> entry : rcvPktListenerList
                .entrySet()) {
            rcvpktlistener = entry.getValue();
            matchAndNotify(rcvpktlistener, pkt);
 
        }          
    }
    
    private String getProtocolDebugMsg(SnbiPkt pkt) {
        StringBuilder sb = new StringBuilder();
        switch (pkt.getmsgType()) {
            case SNBI_MSG_BS_INVITE:
                sb.append("Domain ID:"+pkt.getDomainIDTLV()+" Device ID:"+pkt.getDeviceIDTLV()+"");
                break;
            case SNBI_MSG_BS_REJECT:
                break;
            case SNBI_MSG_BS_REQ:
                break;
            case SNBI_MSG_BS_RESP:
                break;
            case SNBI_MSG_NBR_CONNECT:
                break;
            case SNBI_MSG_ND_BYE:
                break;
            case SNBI_MSG_ND_HELLO:
                break;
            case SNBI_MSG_NI_CERT_REQ:
                break;
            case SNBI_MSG_NI_CERT_RESP:
                break;
            default:
                break;
        
        
        }
        return sb.toString();
    }

    void matchAndNotify (ISnbiMsgInfraPktsListener listener, SnbiPkt pkt) {
        switch (pkt.getmsgType()) {
            case SNBI_MSG_ND_HELLO:
                listener.incomingNDPktsListener(pkt);
                break;
            case SNBI_MSG_NI_CERT_REQ:
                listener.incomingNICertReqPktsListener(pkt);
                break;
            case SNBI_MSG_NI_CERT_RESP:
                listener.incomingNICertRespPktsListener(pkt);
                break;
            case SNBI_MSG_NBR_CONNECT:
                listener.incomingNbrConnectPktsListener(pkt);
                break;
            case SNBI_MSG_BS_REQ:
                listener.incomingBSReqPktsListener(pkt);
                break;
            default:
                log.error("Pkt with invalid message type received "+pkt.getUDITLV()+" msgType "+pkt.getmsgType()+" protocol type "+pkt.getProtocolType());
                break;
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
    private void packetSendInternal(SnbiPkt pkt)
            throws SocketException, IOException {
        DatagramPacket dgramPkt = null;
        NetworkInterface intf = pkt.getEgressInterface();

        try {
            if (intf != null) {
                socket.setNetworkInterface(intf);
            }

            log.debug("OUT packet: Length:"+pkt.getMsgLength()+" UDI: "+pkt.getUDITLV()+"\n\t\t\tProtocol ID:"+pkt.getProtocolType()+
                    " Msg ID:"+pkt.getmsgType()+"\n\t\t\tSRC IP:"+pkt.getSrcIP()+" DST IP:"
                    +pkt.getDstIP()+"\n\t\t\tEgressIntf:"+pkt.getEgressInterface()+"\n\t\t\t"+getProtocolDebugMsg(pkt));
            
            dgramPkt = new DatagramPacket(pkt.getMsg(), pkt.getMsgLength(),
                    pkt.getDstIP(), snbiPortNumber);
            
            socket.send(dgramPkt);
        } catch (Exception excpt) {
            log.error("Failed to send packet "+excpt + " Interface "+((intf == null) ? "null":intf.getDisplayName()));
           
            excpt.printStackTrace();
            throw excpt;
        }
    }

    /**
     * Register a given listener.
     *
     * @return - The handle, which can be used for unregistration as well. The
     *         listener is registered only once, multiple registration will just
     *         ignore the new registration.
     */
    public int registerRcvPktListener(ISnbiMsgInfraPktsListener rcvPktListener) {
        
        rcvPktListenerList.put(rcvPktListener.hashCode(), rcvPktListener);
        
        log.debug("Listener registration success");
        return rcvPktListener.hashCode();
    }

    /**
     * Unregister the listener.
     *
     * @param rcvPktListenerHandle
     *            - The handle that was returned as part of the registration.
     */
    public void unregisterRcvPktListener (int rcvPktListenerHandle) {
        rcvPktListenerList.remove(rcvPktListenerHandle);
    }

    private void socketUninit () {
        if (socket != null) {
            try {
                socket.leaveGroup(SnbiUtils.getIPv6MutlicastAddress());
            } catch (IOException e) {
                log.error("Failed to leave multicast group "+e);
            }
            socket.disconnect();
            socket.close();
            socket = null;
        }
    
        if (pktRcvrThread != null) {
            this.pktRcvrThreadrun = false;
            try {
                pktRcvrThread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    protected void finalize () throws IOException {
        socketUninit();
    }

    public void packetSend(SnbiPkt pkt) throws NullPointerException  {
        if (pkt.getDstIP() == null) {
            throw  new NullPointerException("Destination IP is null");
        }
        try {
            if (pkt.getDstIP().equals(SnbiUtils.getIPv6LoopbackAddress()) || 
                pkt.getDstIP().equals(pkt.getSrcIP())){
                pktRcvdNotifyQueue.put(pkt);
            } else {
               pktSendQueue.put(pkt);
            }
        } catch (Exception excpt) {
            log.error("Failed to send pkt "+excpt);
        }
    }
}
