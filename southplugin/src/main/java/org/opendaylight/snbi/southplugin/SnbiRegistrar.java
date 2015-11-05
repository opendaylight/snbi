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
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.opendaylight.yang.gen.v1.http.netconfcentral.org.ns.snbi.rev240702.snbi.domain.DeviceList;
import org.opendaylight.yang.gen.v1.http.netconfcentral.org.ns.snbi.rev240702.snbi.domain.device.list.Devices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiRegistrar implements ISnbiMsgInfraPktsListener {
    private SnbiNode myNode = null;
    private String domainName = null;
    private int rcvPktEventListenerHandle = 0;
    private static final Logger log = LoggerFactory.getLogger(SnbiRegistrar.class);
    private SnbiMessagingInfra msgInfraInstance = null;
    private ConcurrentHashMap <String, SnbiNode> acceptedNodesList = null;
    private ConcurrentHashMap <String, SnbiNode> rejectedNodesList = null;
    private ConcurrentHashMap <String, SnbiNode> nodesList = null;
    private String nodeRegistrarID;
    private Integer nodeMemberID = 0;
    private final String selfUDI = "PID:JAVA-CONTROLLER SN:1234";

    public SnbiRegistrar (String domainName) {
        try {
        this.domainName = domainName;
        acceptedNodesList = new ConcurrentHashMap <String, SnbiNode>();
        nodesList = new ConcurrentHashMap <String, SnbiNode>();
        rejectedNodesList = new ConcurrentHashMap <String, SnbiNode>();

        msgInfraInstance = SnbiMessagingInfra.getInstance();
        nodeRegistrarID = getFirstValidHostMacAddress();
        //nodeMemberPrefix = "Device";
        this.myNode = SnbiNode.createRegistrarNode(selfUDI, this);
        rcvPktEventListenerHandle = msgInfraInstance.registerRcvPktListener(this);

        } catch (NullPointerException e ) {
            log.error("Null pointer encountered");
            e.printStackTrace();
        }
    }

    // assume there is only one list;
    private  boolean isDeviceinActiveWhiteList(String udi) {
    	HashMap<String, List<DeviceList>> domainInfoMap = CertRegistrar.INSTANCE.getDomainInfoMap();
    	List<DeviceList> deviceLists = domainInfoMap.get(domainName);
		log.debug("Read from Data store for domainName "+domainName);

		if (selfUDI.equals(udi)) {
			return true;
		}

    	for (DeviceList devicelist : deviceLists) {
    		log.debug(" Is active "+devicelist.isActive());
    		log.debug(" List Type "+devicelist.getListType());

    		if (!devicelist.isActive())
    			continue;
    		if (!devicelist.getListType().name().toLowerCase().contains("white"))
    			continue;
    		List<Devices> devices = devicelist.getDevices();

    		for (Devices d : devices) {
    			String str = d.getDeviceId().getValue();
    			log.debug("Device ID being verified "+str+" UDI leng +"+str.length()+" incoming UDI "
    			+udi+" UDI length "+udi.length());


    			if (udi.contains(d.getDeviceId().getValue())) {
    				log.debug("Node UDI validated "+udi);
    				return true;
    			}
    		}
    	}
    	return false;
    }


    public static boolean validateDomain(String domainName) {
    	
    	HashMap<String, List<DeviceList>> domainInfoMap = CertRegistrar.INSTANCE.getDomainInfoMap();

    	if (domainInfoMap.containsKey(domainName))
    		return true;
    	return false;
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



    private void setNodeDeviceID (SnbiNode node) {
        node.setDeviceID(nodeRegistrarID+"-"+nodeMemberID.toString());
        nodeMemberID++;
    }

    public String getRegistrarID () {
        return nodeRegistrarID;
    }

    private void setNodeDeviceIP (SnbiNode node) {
    	try {
    		if (node.nodeIsRegistrar()) {
    			node.setNodeAddress(InetAddress.getByName("fd08::aaaa:bbbb:1"));
    			return;
    		}
    		
    		ByteBuffer ipv6Addr = ByteBuffer.allocate(16);
    		Short prefix = 0xFD;
    		
    		ipv6Addr.put(prefix.byteValue());
    		ipv6Addr.put(getGlobalIDfrmDomainID(this.domainName), 0, 5);
    		ipv6Addr.put(getSubnetID(),0,2);
    		
    		if (node.getDeviceID()== null) {
    			setNodeDeviceID(node);
    		}
    		ipv6Addr.put(node.getDeviceID().getBytes(), 0, 8);
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
    	
    	if (!isDeviceinActiveWhiteList(node.getUDI())) {
    		log.debug("Failed to validate node "+node.getUDI());
    		if (rejectedNodesList == null) {
    			rejectedNodesList = new ConcurrentHashMap <String, SnbiNode>();
    		}
    		if (!rejectedNodesList.containsKey(node.getUDI())) {
    			rejectedNodesList.put(node.getUDI(), node);
    		}
    		return false;
    	}
    	    	
    	if (rejectedNodesList != null && rejectedNodesList.containsKey(node.getUDI())) {
    		rejectedNodesList.remove(node.getUDI());
    	}
    	
    	
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
    
    // Packet event handlers.
    @Override
    public void incomingNodeCertReqPktsListener (SnbiPkt pkt) {
        SnbiNode node = myNode;
        log.debug("[node:"+node.getUDI()+"] NI Cert Req Pkt: "+pkt.getUDITLV());
        if (node.getUDI().equals(pkt.getUDITLV())) {
            node.handleNodeCertReqPktEvent(pkt);
            return;
        }
        log.debug("Cert Req outside UDI din't match pkt UDI:"+pkt.getUDITLV()+"pkt UDI len:"+pkt.getUDITLV().length()+
                " Registrar UDI:"+node.getUDI()+" registrar udi len:"+node.getUDI().length());
    }

    @Override
    public void incomingNodeCertRespPktsListener(SnbiPkt pkt) {
    	log.error("[PktUDI:"+pkt.getUDITLV()+"] Ignoring Received Cert Resp packet");
    }

    @Override
    public void incomingNodeConnectPktsListener(SnbiPkt pkt) {
        SnbiNode node = null;
        if (!nodesList.containsKey(pkt.getUDITLV())) {
        	node = SnbiNode.createNewNode(pkt, this);
        	nodesList.put(node.getUDI(), node);
        } else {
        	node = nodesList.get(pkt.getUDITLV());
        }
        log.debug("[node:"+node.getUDI()+"] NBR Connect Pkt: "+pkt.getUDITLV());

        if (node.getUDI().equals(pkt.getUDITLV()) == false) {
        	log.error("[node:"+node.getUDI()+"] Mismatched with pkt udi "+pkt.getUDITLV());
            return;
        }
        node.handleNodeConnectPktEvent(pkt);
    }

    @Override
	public void incomingNodeBSReqPktsListener (SnbiPkt pkt) {
        SnbiNode node = null;
        if (acceptedNodesList.containsKey(pkt.getUDITLV())) {
            node = acceptedNodesList.get(pkt.getUDITLV());
            log.debug("[node:"+node.getUDI()+"] BS Req: Pkt UDI: "+pkt.getUDITLV());
            node.handleNodeBSReqPktEvent(pkt);
            return;
        }
        log.debug("[node:null] BS Req no such accepted Pkt UDI: "+pkt.getUDITLV());
    }
}
