package org.opendaylight.snbi.southplugin;


import java.net.InetAddress;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiUtils {
    // Logger.
    private static final Logger log = LoggerFactory
            .getLogger(SnbiUtils.class);
    
    // The multicast group that SNBI messages are sent.
    private final static String mcastIPString = "FF02::1";
    // The multicast InetAddress for the mcast IP string.
    private final static String loopbackIPv6String = "::1";
        
    public static InetAddress getIPv6MutlicastAddress () {
        try {
            InetAddress addr = InetAddress.getByName(mcastIPString);
            return addr;
        } catch (UnknownHostException excpt) {
            log.error("Failed to get IPv6 Multicast address "+excpt);
            return null;
        }
    }
    
    public static InetAddress getIPv6LoopbackAddress () {
        try {
            InetAddress addr = InetAddress.getByName(loopbackIPv6String);
            return addr;
        } catch (UnknownHostException excpt) {
            log.error("Failed to get IPv6 Loopback address "+excpt);
            return null;
        }
    }   
}


/**
 * The Message types supported.
 */
enum SnbiMsgType {
    SNBI_MSG_ND_HELLO(1), 
    SNBI_MSG_ND_BYE(2),
    SNBI_MSG_NI_CERT_REQ(3), 
    SNBI_MSG_NI_CERT_RESP(4),
    SNBI_MSG_BS_INVITE(5),
    SNBI_MSG_BS_REJECT(6),
    SNBI_MSG_BS_REQ(7),
    SNBI_MSG_BS_RESP(8),
    SNBI_MSG_NBR_CONNECT(10);
    private Integer value;

    private SnbiMsgType(Integer value) {
        this.value = value;
    }

    /**
     * Get the value of the enum.
     * @return
     */
    public Integer getValue() {
        return (value);
    }

    /**
     * Get the enum from the value.
     * @param value - The value of the enum.
     * @return - The enum corresponding to the value.
     */
    public static SnbiMsgType getEnumFromValue(int value) {
        for (SnbiMsgType type : SnbiMsgType.values()) {
            if (type.getValue() == value)
                return type;
        }
        return null;
    }
}

/**
 * The TLV types supported.
 */
enum SnbiTLVType {
    SNBI_TLV_TYPE_UDI((short) 1),
    SNBI_TLV_TYPE_CERTIFICATE((short)3),
    SNBI_TLV_TYPE_DEVICE_ID((short)4),
    SNBI_TLV_TYPE_DOMAIN_ID((short)5),
    SNBI_TLV_TYPE_IF_IPADDR((short) 6), 
    SNBI_TLV_TYPE_IF_NAME((short) 7),
    SNBI_TLV_TYPE_REGISTRAR_IPADDR((short)9);

    private Short value;

    private SnbiTLVType(short value) {
        this.value = value;
    }

    /**
     * Get the value of the enum.
     * @return - The value of the enum.
     */
    public Short getValue() {
        return this.value;
    }

    /**
     * Get the enum corresponding to a value.
     * @param value - The value of the enum.
     * @return - The enum corresponding to the value.
     */
    public static SnbiTLVType getEnumFromValue(short value) {
        for (SnbiTLVType type : SnbiTLVType.values()) {
            if (type.getValue() == value)
                return type;
        }
        return null;
    }
}

enum SnbiTLVSubtypeCertificate {
    SNBI_TLV_STYPE_SUDI ((short)1),
    SNBI_TLV_STYPE_DOMAIN_CERT((short)2),
    SNBI_TLV_STYPE_REGISTERAR_CERT((short)3),
    SNBI_TLV_STYPE_CA_CERT((short)4);
    
    private Short value;

    private SnbiTLVSubtypeCertificate(short value) {
        this.value = value;
    }

    /**
     * Get the value of the enum.
     * @return - The value of the enum.
     */
    public Short getValue() {
        return this.value;
    }

    /**
     * Get the enum corresponding to the value.
     * @param value - The value of the enum.
     * @return - The enum corresponding to the value.
     */
    public static SnbiTLVSubtypeCertificate getEnumFromValue(short value) {
        for (SnbiTLVSubtypeCertificate type : SnbiTLVSubtypeCertificate.values()) {
            if (type.getValue() == value)
                return type;
        }
        return null;
    }
}

/**
 * Subtype UDI.
 */
enum SnbiTLVSubtypeUDI {
    SNBI_TLV_STYPE_UDI((short) 1);
    private Short value;

    private SnbiTLVSubtypeUDI(short value) {
        this.value = value;
    }

    /**
     * Get the value of the enum.
     * @return - The value of the enum.
     */
    public Short getValue() {
        return this.value;
    }

    /**
     * Get the enum corresponding to the value.
     * @param value - The value of the enum.
     * @return - The enum corresponding to the value.
     */
    public static SnbiTLVSubtypeUDI getEnumFromValue(short value) {
        for (SnbiTLVSubtypeUDI type : SnbiTLVSubtypeUDI.values()) {
            if (type.getValue() == value)
                return type;
        }
        return null;
    }
}

/**
 * Subtype UDI.
 */
enum SnbiTLVSubtypeDomainID {
    SNBI_TLV_STYPE_DOMAIN_ID((short) 1);
    private Short value;

    private SnbiTLVSubtypeDomainID(short value) {
        this.value = value;
    }

    /**
     * Get the value of the enum.
     * @return - The value of the enum.
     */
    public Short getValue() {
        return this.value;
    }

    /**
     * Get the enum corresponding to the value.
     * @param value - The value of the enum.
     * @return - The enum corresponding to the value.
     */
    public static SnbiTLVSubtypeDomainID getEnumFromValue(short value) {
        for (SnbiTLVSubtypeDomainID type : SnbiTLVSubtypeDomainID.values()) {
            if (type.getValue() == value)
                return type;
        }
        return null;
    }
}

/**
 * Subtype Device ID.
 */
enum SnbiTLVSubtypeDeviceID {
    SNBI_TLV_STYPE_DEVICE_ID((short) 1);
    private Short value;

    private SnbiTLVSubtypeDeviceID(short value) {
        this.value = value;
    }

    /**
     * Get the value of the enum.
     * @return - The value of the enum.
     */
    public Short getValue() {
        return this.value;
    }

    /**
     * Get the enum corresponding to the value.
     * @param value - The value of the enum.
     * @return - The enum corresponding to the value.
     */
    public static SnbiTLVSubtypeDeviceID getEnumFromValue(short value) {
        for (SnbiTLVSubtypeDeviceID type : SnbiTLVSubtypeDeviceID.values()) {
            if (type.getValue() == value)
                return type;
        }
        return null;
    }
}

/**
 * IP address Subtypes.
 */
enum SnbiTLVSubtypeIPaddr {
    SNBI_TLV_STYPE_IPV4_ADDR((short) 1), SNBI_TLV_STYPE_IPV6_ADDR((short) 2);
    private Short value;

    private SnbiTLVSubtypeIPaddr(short value) {
        this.value = value;
    }
    /**
     * Get the value of the enum.
     * @return - The value of the enum.
     */
    public Short getValue() {
        return this.value;
    }

    /**
     * Get the enum corresponding to the value.
     * @param value - The value of the enum.
     * @return - The enum corresponding to the value.
     */
    public static SnbiTLVSubtypeIPaddr getEnumFromValue(short value) {
        for (SnbiTLVSubtypeIPaddr type : SnbiTLVSubtypeIPaddr.values()) {
            if (type.getValue() == value)
                return type;
        }
        return null;
    }
}

enum SnbiTLVSubtypeIfName {
    SNBI_TLV_STYPE_IF_NAME((short) 1);
    private Short value;

    private SnbiTLVSubtypeIfName(short value) {
        this.value = value;
    }
    /**
     * Get the value of the enum.
     * @return - The value of the enum.
     */
    public Short getValue() {
        return this.value;
    }

    /**
     * Get the enum corresponding to the value.
     * @param value - The value of the enum.
     * @return - The enum corresponding to the value.
     */
    public static SnbiTLVSubtypeIfName getEnumFromValue(short value) {
        for (SnbiTLVSubtypeIfName type : SnbiTLVSubtypeIfName.values()) {
            if (type.getValue() == value)
                return type;
        }
        return null;
    }
}

/**
 * The protocol types.
 */
enum SnbiProtocolType {
    SNBI_PROTOCOL_ADJACENCY_DISCOVERY((short) 2),
    SNBI_PROTOCOL_BOOTSTRAP ((short)3);
    private Short value;

    SnbiProtocolType(short value) {
        this.value = value;
    }
    /**
     * Get the value of the enum.
     * @return - The value of the enum.
     */
    public Short getValue() {
        return value;
    }

    /**
     * Get the enum corresponding to the value.
     * @param value - The value of the enum.
     * @return - The enum corresponding to the value.
     */
    public static SnbiProtocolType getEnumFromValue(short value) {
        for (SnbiProtocolType type : SnbiProtocolType.values()) {
            if (type.getValue() == value)
                return type;
        }
        return null;
    }
}