package org.opendaylight.snbi.southplugin;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiRegistrar implements ISnbiMsgInfraPktsListener, ISnbiNodeEventsListener {
    private SnbiNode myNode = null;
    private String domainName = null;
    private int rcvPktEventListenerHandle = 0;
    private static final Logger log = LoggerFactory.getLogger(SnbiRegistrar.class);
    private SnbiMessagingInfra msgInfraInstance = null;
    private ConcurrentHashMap <String, SnbiNode> acceptedNodesList = null;
    private ConcurrentHashMap <String, SnbiNode> nbrNodesList = null;
    private String nodeRegistrarID;
    private Integer nodeMemberID = 0;
    
    public SnbiRegistrar (String domainName) {
        try {
        this.domainName = domainName;
        acceptedNodesList = new ConcurrentHashMap <String, SnbiNode>();
        nbrNodesList = new ConcurrentHashMap <String, SnbiNode>();

        msgInfraInstance = SnbiMessagingInfra.getInstance();
        nodeRegistrarID = getFirstValidHostMacAddress();
        //nodeMemberPrefix = "Device";
        this.myNode = SnbiNode.createRegistrarNode("PID:JAVA-CONTROLLER SN:1234", this);
        rcvPktEventListenerHandle = msgInfraInstance.registerRcvPktListener(this);

        } catch (NullPointerException e ) {
            log.error("Null pointer encountered");
            e.printStackTrace();
        }
    }
    
    private String getFirstValidHostMacAddress () {
        Enumeration<NetworkInterface> networkIntfs;
        try {
            networkIntfs = NetworkInterface.getNetworkInterfaces();
            while(networkIntfs.hasMoreElements()) {
                NetworkInterface intf = networkIntfs.nextElement();
                byte[] mac;
                
                mac = intf.getHardwareAddress();  
                if(mac != null) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < mac.length; i++) {
                        sb.append(String.format("%02x%s", mac[i], (((i+1) % 2 == 0) && (i < (mac.length - 1) ) ) ? "." : ""));        
                    }
                    sb.append(String.format("%c", '\0'));
                    return sb.toString();
                }
            }
        } catch (SocketException e) {
            log.error("Failed to get Network Interfaces");
            return null;
        }
        
        return null;
    }
    
    public SnbiMessagingInfra getMsgInstance () {
        return msgInfraInstance;
    }
    
    public String getDomainName () {
        return domainName;
    }
           
    public SnbiNode getNodeself () {
        return myNode;
    }
    
    public List <SnbiNode> getNeighborNodes() {
        return new ArrayList <SnbiNode>((nbrNodesList.values()));
    }

    @Override
    public void incomingNDPktsListener(SnbiPkt pkt) {
        SnbiNode node = null;
        if (nbrNodesList.containsKey(pkt.getUDITLV())) {
            node = nbrNodesList.get(pkt.getUDITLV());
            log.debug("[node: "+node.getUDI()+"] Recived ND pkts: "+pkt.getUDITLV());
            node.handleNDRefreshPktEvent(pkt);
        } else {
            node = SnbiNode.createNeighborNode(pkt, this);
            nbrNodesList.put(node.getUDI(), node);
            log.debug("[node: "+node.getUDI()+"] Recived ND pkts: "+pkt.getUDITLV());
        }
    }
    
    @Override
    public void neighborNodeLostEventListener(SnbiNode node) {
        log.debug("[node: "+node.getUDI()+"] Neighbor node lost: "+node.getUDI());
        nbrNodesList.remove(node.getUDI());
    }

    @Override
    public void incomingNICertReqPktsListener(SnbiPkt pkt) {
        SnbiNode node = myNode;
        log.debug("[node: "+node.getUDI()+"] NI Cert Req Pkt: "+pkt.getUDITLV());
        if (node.getUDI().equals(pkt.getUDITLV())) {
            node.handleNICertReqPktEvent(pkt);        
            return;
        }
        log.debug("Cert Req outside UDI din't match pkt UDI:"+pkt.getUDITLV()+"pkt UDI len:"+pkt.getUDITLV().length()+
                " Registrar UDI:"+node.getUDI()+" registrar udi len:"+node.getUDI().length());
    }

    @Override
    public void incomingNICertRespPktsListener(SnbiPkt pkt) {
        SnbiNode node = null;
        if (nbrNodesList.containsKey(pkt.getUDITLV())) {
            node = nbrNodesList.get(pkt.getUDITLV());
            node.handleNICertRespPktEvent(pkt);
            log.debug("[node: "+node.getUDI()+"] NI Cert Resp Pkt: "+pkt.getUDITLV());

        } else {
            node = SnbiNode.createNeighborNode(pkt, this);
            nbrNodesList.put(node.getUDI(), node);
        }        
    }

    @Override
    public void incomingNbrConnectPktsListener(SnbiPkt pkt) {
        SnbiNode node = myNode;
        log.debug("[node: "+node.getUDI()+"] NBR Connect Pkt: "+pkt.getUDITLV());

        if (node.getUDI() != pkt.getUDITLV()) {
            return;
        }
        node.handleNbrConnectPktEvent(pkt);
    }
    
    public void incomingBSReqPktsListener (SnbiPkt pkt) {
        SnbiNode node = null;
        if (acceptedNodesList.containsKey(pkt.getUDITLV())) {
            node = acceptedNodesList.get(pkt.getUDITLV());
            log.debug("[node: "+node.getUDI()+"] BS Req: Pkt UDI: "+pkt.getUDITLV());
            node.handleBSReqPktEvent(pkt);
            return;
        }
        log.debug("[node: null] BS Req no such accepted node: Pkt UDI: "+pkt.getUDITLV());

    }

    private void setNodeDeviceID(SnbiNode node) {
        node.setDeviceID(nodeRegistrarID+"-"+nodeMemberID.toString());
        nodeMemberID++;
    }
    
    public String getRegistrarID () {
        return nodeRegistrarID;
    }
    
    private void setNodeDeviceIP (SnbiNode node) {      
        ByteBuffer ipv6Addr = ByteBuffer.allocate(16);
        Short prefix = 0xFD;

        ipv6Addr.put(prefix.byteValue());
        ipv6Addr.put(getGlobalIDfrmDomainID(this.domainName), 0, 5);
        ipv6Addr.put(getSubnetID(),0,2);
        
        if (node.getDeviceID()== null) {
            setNodeDeviceID(node);
        }
        ipv6Addr.put(node.getDeviceID().getBytes(), 0, 8);
        
        try {
            node.setNodeAddress(InetAddress.getByAddress(ipv6Addr.array()));
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }
    private byte[] getSubnetID () {
        byte[] subnetID = new byte[2];
        subnetID[0] = subnetID[1] = 0;
        //TODO
        return subnetID;
    }
    private byte[] getGlobalIDfrmDomainID (String domainName) {
        MessageDigest md;
        
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to generate Global ID ");
            return null;
        }
        return (md.digest(domainName.getBytes()));
    }

    public boolean validateNode(SnbiNode node) {
        if (acceptedNodesList == null) {
            acceptedNodesList = new ConcurrentHashMap <String, SnbiNode>(); 
        }
        if (!acceptedNodesList.containsKey(node.getUDI())) {
            acceptedNodesList.put(node.getUDI(), node);
            setNodeDeviceID(node);
            setNodeDeviceIP(node);
        }
        return true;        
    }
}
