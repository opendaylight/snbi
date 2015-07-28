package org.opendaylight.snbi.southplugin;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiPkt {
    // logger
    private static final Logger log = LoggerFactory
            .getLogger(SnbiInternal.class);
    // 4 bit protocol version field.
    private byte protocolVersion;
    // 4 bit reserved bits.
    private byte reservedBits;
    // 8 bits protocol type.
    private SnbiProtocolType protocolType;
    // 8 bit reserved flags.
    private Short flags;
    // 8 bits hop limit, number of hops a message can traverse.
    private Short hopLimit;
    // 16 bits Msg type.
    private SnbiMsgType msgType;
    // 16 bit msg length.
    private Integer msgLength;
    // 16 bits msg number.
    private Integer msgNumber;
    // 16 bits reserver bits.
    private Integer reserved_2;
    // TLV hash list.
    private Map<Integer, TLV> TLVHashList = null;
    // src IP address
    private InetAddress srcIP;
    // Dst IP address
    private InetAddress dstIP;

    /*
     * Header length is a combination of the following. protocol version (4bits)
     * + reserved bits (4bits) + protocol type (8bits) + flags (8bits) +
     * hoplimit (8bits) + message type (16bits) + msglength (16bits) + msgNumber (16bits) + 
     * reserved_2 (16bits)
     */
    private static final byte SNBIHEADERLENGTH = 12;
    /*
     * The interface on which the packet was received on.
     */
    private NetworkInterface ingressIntf = null;
    private NetworkInterface egressIntf = null;

    /**
     * Constructor to create an SNBI packet from the protocol type and message
     * type.
     *
     * @param protocolType
     *            - The protocol type of the message to be transmitted or
     *            received.
     * @param msgType
     *            - The message type of the message to be transmitted or
     *            received.
     */
    public SnbiPkt(SnbiProtocolType protocolType, SnbiMsgType msgType) {
        initPkt();
        this.protocolVersion = 1;
        this.reservedBits = 0;
        this.protocolType = protocolType;
        this.msgType = msgType;
        // 1 byte reservedBits + ProtocolVersion, 1 byte protocolType, 1 byte
        // flags, 1 byte hoplimit, 2 bytes msgType, 2 byte msglength.
        this.msgLength = (int) SNBIHEADERLENGTH;
    }
    
    
    /**
     * Create an SNBI packet from the byte stream received.
     *
     * @param rcvStream
     *            - The byte stream.
     * @param msgLength
     *            - The length of the received data.
     * @throws BufferOverflowException
     */
    public SnbiPkt(byte[] rcvStream, int msgLength)
            throws BufferOverflowException {
    
        if (rcvStream == null || msgLength == 0) {
            return;
        }
        
        initPkt();
    
        try {
            ByteBuffer msgByteStream = null;
            msgByteStream = ByteBuffer.allocate(msgLength);
            msgByteStream.put(rcvStream, 0, msgLength);
            msgByteStream.flip();
            parseMsgByteStream(msgByteStream);
        } catch (BufferOverflowException excpt) {
            log.error("Buffer overflow exception " + excpt);
            throw excpt;
        }
   
    }
    
    private void initPkt () {
        this.protocolVersion = 1;
        this.reservedBits = 0;
        this.hopLimit = 255;
        // 1 byte reservedBits + ProtocolVersion, 1 byte protocolType, 1 byte
        // flags, 1 byte hoplimit, 2 bytes msgType, 2 byte msglength.
        this.msgLength = 0;
        this.flags = 0;
        this.msgNumber = 0;
        this.reserved_2 = 0;
        this.srcIP = null;
        this.dstIP = null;
        this.ingressIntf = null;
        this.egressIntf = null;
        this.TLVHashList = new HashMap<Integer, TLV>();
    }

    /*
     * Parse the message stream received.
     */
    private void parseMsgByteStream(ByteBuffer msgByteStream) {
        parseMsgHeader(msgByteStream);
        parseMsgTLVs(msgByteStream);
    }

    /*
     * Parse the message headers.
     */
    private void parseMsgHeader(ByteBuffer msgByteStream) {
        Byte byteval;
        int reservedVersion = msgByteStream.get();
        // Get the first byte reserver bit + protocol version.
        reservedBits = (byte) (reservedVersion & 0x000f);
        protocolVersion = (byte) (reservedVersion >> 4 & 0x000f);
        protocolType = SnbiProtocolType.getEnumFromValue((short) msgByteStream
                .get());
        flags = (short) msgByteStream.get();
        byteval = msgByteStream.get();
        hopLimit = byteval.shortValue();
        msgType = SnbiMsgType.getEnumFromValue((int) msgByteStream.getShort());
        msgLength = (int) msgByteStream.getShort();
        msgNumber = (int) msgByteStream.getShort();
        reserved_2 = (int) msgByteStream.getShort();
    }

    /*
     * Parse the TLVs.
     */
    private void parseMsgTLVs(ByteBuffer msgByteStream) {
        TLV tlv = null;
        int tlvType;
        int length;
        byte[] value = null;
        // For now we assume that we have parsed over the headers. Parse the
        // TLVs now.
        while (msgByteStream.hasRemaining()) {
            tlvType = msgByteStream.getShort();
            length = msgByteStream.getShort() - TLV.SNBITLVHEADERLENGTH;
            value = new byte[length];
            msgByteStream.get(value);
            tlv = new TLV(tlvType, value, length);
            // Only add the TLV, no need to increment the message length.
            addTLVInternal(tlv);
        }
    }

    /**
     * The network interface on which the packet should be sent out on.
     *
     * @param intf
     *            - The interface on which the packet should be sent out on or
     *            received from.
     */
    public void setIngressInterface(NetworkInterface intf) {
        this.ingressIntf = intf;
    }

    public void setEgressInterface(NetworkInterface intf) {
        this.egressIntf = intf;
    }

    
    /**
     * Get the network interface.
     *
     * @return - The network interface that is set on the packet.
     */
    public NetworkInterface getIngressInterface() {
        return (this.ingressIntf);
    }
    
    public NetworkInterface getEgressInterface() {
        return (this.egressIntf);
    }

    public InetAddress getSrcIP () {
        return this.srcIP;
    }
    
    public void setSrcIP (InetAddress addr) {
        this.srcIP = addr;
    }
    
    
    public InetAddress getDstIP () {
        return this.dstIP;
    }
    
    public void setDstIP (InetAddress addr) {
        this.dstIP = addr;
    }

    /**
     * Get the current message length of the packet.
     *
     * @return The message length.
     */
    public int getMsgLength() {
        return msgLength;
    }

    /**
     * Get the message type of the packet.
     *
     * @return - The message type of the packet.
     */
    public SnbiMsgType getmsgType() {
        return msgType;
    }

    /**
     * Get the version field in the packet.
     *
     * @return - The version field of the message.
     */
    public byte getVersion() {
        return protocolVersion;
    }

    /**
     * Get the protocol type of the message.
     *
     * @return - The protocol type.
     */
    public SnbiProtocolType getProtocolType() {
        return protocolType;
    }

    /**
     * Get a byte stream message constructed from the set of the TLVs and SNBI
     * header.
     *
     * @return - The byte stream.
     */
    public byte[] getMsg() {
        ByteBuffer msgByteStream = null;
        msgByteStream = ByteBuffer.allocate(this.msgLength);
        updateByteStreamWithMsgHeader(msgByteStream);
        updateByteStreamWithMsgTLVs(msgByteStream);
        return msgByteStream.array();
    }

    private void updateByteStreamWithMsgHeader(ByteBuffer msgByteStream) {
        if (msgByteStream == null) {
            return;
        }
        msgByteStream.put((byte) (reservedBits | protocolVersion << 4));
        msgByteStream.put(protocolType.getValue().byteValue());
        msgByteStream.put(flags.byteValue());
        msgByteStream.put(hopLimit.byteValue());
        msgByteStream.putShort(msgType.getValue().shortValue());
        msgByteStream.putShort(msgLength.shortValue());
        msgByteStream.putShort(msgNumber.shortValue());
        msgByteStream.putShort(reserved_2.shortValue());
    }

    private void updateByteStreamWithMsgTLVs(ByteBuffer msgByteStream) {
        short tlvlength = 0;
        if (msgByteStream == null) {
            return;
        }
        for (Entry<Integer, TLV> TLVlistEntry : TLVHashList.entrySet()) {
        	TLV tlv = TLVlistEntry.getValue();
        	msgByteStream.putShort(tlv.getType().shortValue());
        	tlvlength = (short) (TLV.SNBITLVHEADERLENGTH + tlv.getLength()
        			.shortValue());
        	msgByteStream.putShort(tlvlength);
        	msgByteStream.put(tlv.getValue());	
        }
    }
    
    public String getIfNameTLV () {
    	Short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue == SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue()) {        
    		return (this.getStringTLV(SnbiNdTlvType.SNBI_ND_TLV_TYPE_IF_NAME.getValue()));
    	} else {
    		log.error("Cannot setIfName for protocol type "+this.protocolType);
    	}
    	return null;
    }

    // Add the Interface name to the TLV list.
    public void setIfNameTLV (NetworkInterface intf) {
    	Short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue == SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue()) {        
    		this.setStringTLV(SnbiNdTlvType.SNBI_ND_TLV_TYPE_IF_NAME.getValue(), intf.getName());
    	} else {
    		log.error("Cannot setIfName for protocol type "+this.protocolType);
    	}
    }
    
    private void addIPV6addrTLV (int type, InetAddress inetAddress) {
        this.addTLV(new TLV (type, inetAddress.getAddress(), 
                             inetAddress.getAddress().length));
    }

    // Add the link local address to the TLV list.
    public void setIPV6LLTLV (NetworkInterface intf) {
    	Short protocolValue = this.protocolType.getValue();
    	Enumeration<InetAddress> inetAddresses = intf.getInetAddresses();
    	
        for (InetAddress inetAddress : Collections.list(inetAddresses)) {
            if (inetAddress.isLinkLocalAddress()) {
            	if (protocolValue == 
            			SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue()) {
            		addIPV6addrTLV(SnbiNdTlvType.SNBI_ND_TLV_TYPE_IF_V6ADDR.getValue(),
            				inetAddress);
            	} else if (protocolValue == 
            			SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
            		addIPV6addrTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_IF_V6ADDR.getValue(),
            				inetAddress);
            	} else {
            		log.error("Cannot set IPV6LLTLV for protocol type "+this.protocolType);
            	}
            	return;
            }
        }
    }
    
    public InetAddress getIPV6LLTLV () {
    	Short protocolValue = this.protocolType.getValue();
    	int tlvType = 0;
    	if (protocolValue == 
    			SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue()) {
    		tlvType = SnbiNdTlvType.SNBI_ND_TLV_TYPE_IF_V6ADDR.getValue();
    	} else if (protocolValue == 
    			SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
    		tlvType = SnbiBsTlvType.SNBI_BS_TLV_TYPE_IF_V6ADDR.getValue();
    	} else {
    		log.error("Cannot get IPV6LLTLV for protocol type "+this.protocolType);
    		return null;
    	}
        return getIPTLV(tlvType);
    }

    /**
     * Get the first string value in the TLV list corresponding to a type.
     *
     * @param type
     *            - The type of the TLV.
     * @param stype
     *            - The subtype of the TLV.
     * @return - The TLV string corresponding to a type and subtype.
     */
    private String getStringTLV(int type) {
        TLV tlv = getTLV(type);
        if (tlv == null) {
            return null;
        }
        return new String(tlv.getValue());
    }
    
    private void setStringTLV (int type, String str) {
    	// Stupid FE implementation requires null terminating string as well.
    	byte nullCh = 0;
    	int strByteLength = str.getBytes().length;
    	byte[] tmpStrByteArr = new byte[strByteLength+1];
        System.arraycopy(str.getBytes(), 0, tmpStrByteArr, 0, strByteLength);  
        tmpStrByteArr[strByteLength] = nullCh;
        this.addTLV(new TLV(type, tmpStrByteArr,tmpStrByteArr.length));
    }
    

    public String getUDITLV () {
    	short protocolValue = this.protocolType.getValue();
    	   	
    	if (protocolValue == 
    		SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue()) {
    		return (getStringTLV(SnbiNdTlvType.SNBI_ND_TLV_TYPE_UDI.getValue()));
    	} else if (protocolValue == SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
    		return (getStringTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_UDI.getValue()));
    	} 
    	log.error("Cannot get UDITLV for protocol type "+this.protocolType);
    	return null;
    }
    
    public void setUDITLV(String udi) {
    	short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue == 
    		SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue() ) {
    		setStringTLV(SnbiNdTlvType.SNBI_ND_TLV_TYPE_UDI.getValue(), udi);
    	} else if (protocolValue == SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
            setStringTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_UDI.getValue(), 
                         udi);
    	} else {
        	log.error("Cannot set UDITLV for protocol type "+this.protocolType);
    	}

    }

    /**
     * Get the TLV list of a particular type.
     *
     * @param type
     *            - The type of the TLV.
     * @return the TLV list for a particular type.
     */
    public TLV getTLV(int type) {
        if (TLVHashList == null) {
            return null;
        }
        return TLVHashList.get(type);
    }

    private void addTLVInternal(TLV tlv) {
        if (TLVHashList == null) {
            this.TLVHashList = new HashMap<Integer, TLV>();
        }
        
        TLVHashList.put(tlv.getType(), tlv);
    }
    
    private InetAddress getIPTLV (int type) {
    	TLV tlv = getTLV(type);
    	
        if (tlv == null) {
            return null;
        }       
        try {
            return InetAddress.getByAddress(tlv.getValue());
        } catch (UnknownHostException e) {
            return null;
        }
    }

    public void setDeviceIDTLV(String deviceID) {
    	short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue == 
    		SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue() ) {
    		this.setStringTLV(SnbiNdTlvType.SNBI_ND_TLV_TYPE_DEVICE_ID.getValue(),  
                    deviceID);
    	} else if (protocolValue == SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
     		this.setStringTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_DEVICE_ID.getValue(),  
                    deviceID);
    	} else {
        	log.error("Cannot set DeviceID for protocol type "+this.protocolType);
    	}
    }
    
    public String getDeviceIDTLV() {
    	short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue == 
    		SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue() ) {
    		return this.getStringTLV(SnbiNdTlvType.SNBI_ND_TLV_TYPE_DEVICE_ID.getValue());
    	} else if (protocolValue == SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
    		return this.getStringTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_DEVICE_ID.getValue());
    	} else {
        	log.error("Cannot get DeviceID for protocol type "+this.protocolType);
    	}
    	return null;
    }
    
    public String getDomainIDTLV() {
    	short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue == 
    		SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue() ) {
    		return this.getStringTLV(SnbiNdTlvType.SNBI_ND_TLV_TYPE_DOMAIN_ID.getValue());
    	} else if (protocolValue == SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
    		return this.getStringTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_DOMAIN_ID.getValue());
    	} else {
        	log.error("Cannot get DomainID for protocol type "+this.protocolType);
    	}
    	return null;
    }

    public void setDomainIDTLV(String domainName) {
    	short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue == 
    		SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue() ) {
    		this.setStringTLV(SnbiNdTlvType.SNBI_ND_TLV_TYPE_DOMAIN_ID.getValue(),domainName);
    	} else if (protocolValue == SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
    		this.setStringTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_DOMAIN_ID.getValue(),domainName);
    	} else {
        	log.error("Cannot set UDITLV for protocol type "+this.protocolType);
    	}
    }

    public void setRegistrarIPaddrTLV(InetAddress addr) {
    	short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue != 
    		SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue() ) {
        	log.error("Cannot add registart IP for protocol type "+this.protocolType);
    	}
    	addIPV6addrTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_RA_V6ADDR.getValue(), addr);
    }
    
    public InetAddress getRegistrarIPaddrTLV () {
    	InetAddress inetaddr;
    	short protocolValue = this.protocolType.getValue();
    	int tlvType;
    	
    	if (protocolValue == SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
    		tlvType = SnbiBsTlvType.SNBI_BS_TLV_TYPE_RA_V6ADDR.getValue();
    		inetaddr = getIPTLV(tlvType);
    		if (inetaddr == null) {
    			// if there is no IPV6 address try IPV4.
    			tlvType = SnbiBsTlvType.SNBI_BS_TLV_TYPE_IF_V4ADDR.getValue();
    			inetaddr = getIPTLV(tlvType);
    		}
    		return inetaddr;
    	} else {
        	log.error("Cannot set UDITLV for protocol type "+this.protocolType);
    	}
    	return null;
    }

    private void addCertTLV(Integer type, X509Certificate cert) {
        byte[] certDer = null;
        try {
            certDer = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            log.error("Failed to add DER TLV type "+type);
            e.printStackTrace();
        }
        this.addTLV(new TLV (type, certDer, certDer.length));
    }

    private X509Certificate getCertTLV (int type) {
        TLV tlv = getTLV (type);
        if (tlv == null) {
        	return null;
        }
        try {
        	ByteArrayInputStream bis = new ByteArrayInputStream(tlv.getValue());
        	CertificateFactory cf
        	= CertificateFactory.getInstance("X.509");
        	return (java.security.cert.X509Certificate)cf.generateCertificate(bis);
        } catch (CertificateException e) {
        	log.error("Failed to obtain certificate of type "+type);
        	e.printStackTrace();
        }
        return null;
    }
    
    public void setCACertTLV(X509Certificate x509Certificate) {
    	short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue != 
    		SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue() ) {
        	log.error("Cannot set CA certTLV for protocol type "+this.protocolType);
        	return;
    	}
        addCertTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_CA_CERTIFICATE.getValue(), x509Certificate);
    }
    
    public X509Certificate getCACertTLV () {
   	    short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue != 
    		SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue() ) {
        	log.error("Cannot get CA certTLV for protocol type "+this.protocolType);
        	return null;
    	}
        return getCertTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_CA_CERTIFICATE.getValue());
    }

    /**
     * Add a TLV to the message.
     *
     * @param tlv
     *            - The TLV to be added.
     */
    private void addTLV(TLV tlv) {
        // Update the message length.
        this.msgLength += (TLV.SNBITLVHEADERLENGTH + tlv.getLength());
        addTLVInternal(tlv);
    }

    public void setRegistrarCertTLV(X509Certificate cert) {
   	    short protocolValue = this.protocolType.getValue();

       	if (protocolValue != 
        	SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
       		log.error("Cannot set registar certTLV for protocol type "+this.protocolType);
       		return;
       	}
        addCertTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_RA_CERTIFICATE.getValue(), cert);
    }
    
    public X509Certificate getDomainCertTLV() {
  	    short protocolValue = this.protocolType.getValue();

       	if (protocolValue != 
        	SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
       		log.error("Cannot get Domain certTLV for protocol type "+this.protocolType);
       		return null;
       	}
        return getCertTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_DOMAIN_CERTIFICATE.getValue());
    }


    public void setDomainCertTLV(X509Certificate cert) {
 	    short protocolValue = this.protocolType.getValue();

       	if (protocolValue != 
        	SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
       		log.error("Cannot set Domain certTLV for protocol type "+this.protocolType);
       		return;
       	}
        addCertTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_DOMAIN_CERTIFICATE.getValue(), cert);
    }
    
    public PKCS10CertificationRequest getPKCS10CSRTLV () {
	    short protocolValue = this.protocolType.getValue();

       	if (protocolValue != 
        	SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
       		log.error("Cannot get pkc10 req for protocol type "+this.protocolType);
       		return null;
       	}
       	
        TLV tlv = getTLV (SnbiBsTlvType.SNBI_BS_TLV_TYPE_CERT_REQ.getValue());
        	
        try {
        	PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(tlv.getValue());
        	return pkcs10;
        } catch (IOException e) {
        	log.error("Failed to obtain PKCS10 from packet");
        	e.printStackTrace();
        	return null;
        }
    }


    public void setRegistrarIDTLV(String registrarID) {
	    short protocolValue = this.protocolType.getValue();

       	if (protocolValue != 
        	SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP.getValue()) {
       		log.error("Cannot set registar ID for protocol type "+this.protocolType);
       		return ;
       	}
       	
        this.setStringTLV(SnbiBsTlvType.SNBI_BS_TLV_TYPE_RA_ID.getValue(),
                registrarID);  
    }


	public void setDeviceIPv6TLV(InetAddress nodeAddress) {
		short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue == 
    		SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue() ) {
    		addIPV6addrTLV(SnbiNdTlvType.SNBI_ND_TLV_TYPE_DEVICE_V6ADDR.getValue(),
    				nodeAddress);
    	} else {
        	log.error("Cannot set UDITLV for protocol type "+this.protocolType);
    	}
	}


	public InetAddress gettDeviceIPv6TLV() {
		short protocolValue = this.protocolType.getValue();
    	
    	if (protocolValue == 
    		SnbiProtocolType.SNBI_PROTOCOL_ADJACENCY_DISCOVERY.getValue() ) {
    		return (getIPTLV(SnbiNdTlvType.SNBI_ND_TLV_TYPE_DEVICE_V6ADDR.getValue()));    	
    	} else {
        	log.error("Cannot set UDITLV for protocol type "+this.protocolType);
        }		
    	return null;
	}
}

/**
 * SNBI TLV class This is different from the normal type in that it contains a
 * type.
 */
class TLV {
    private Integer type; // 16 bits + 2 byte = 32 bits.
    private Integer length; // 16 bits + 2 byte = 32 bits
    private byte[] value;
    /*
     * TLV header length Type (16 bits) + Length (16bits).
     */
    public static final byte SNBITLVHEADERLENGTH = 4;

    /**
     * create TLV with the given type, subtype, value and length.
     *
     * @param type
     * @param value
     * @param length
     */
    public TLV(Integer type, byte[] value, Integer length) {
        this.type = type;
        this.length = length;
        this.value = value;
    }

    /**
     * Get the type of the TLV.
     */
    public Integer getType() {
        return type;
    }

    /**
     * Get the length of the value.
     *
     * @return - The length of the value.
     */
    public Integer getLength() {
        return length;
    }

    /**
     * Get the value of the TLV.
     *
     * @return - The value of the TLV.
     */
    public byte[] getValue() {
        return value;
    }
}
