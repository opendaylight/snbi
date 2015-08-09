/*
 * Copyright (c) 2014, 2015 Cisco Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

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
    private final static String mcastIPString = "FF02::150";
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

enum SnbiNdTlvType {
	SNBI_ND_TLV_TYPE_INVALID(0),
	SNBI_ND_TLV_TYPE_UDI(1),
	SNBI_ND_TLV_TYPE_DEVICE_ID(2),
	SNBI_ND_TLV_TYPE_DOMAIN_ID(3),
	SNBI_ND_TLV_TYPE_DEVICE_V4ADDR(4),
	SNBI_ND_TLV_TYPE_DEVICE_V6ADDR(5),
	SNBI_ND_TLV_TYPE_IF_V4ADDR(6),
	SNBI_ND_TLV_TYPE_IF_V6ADDR(7),
	SNBI_ND_TLV_TYPE_IF_NAME(8),
	SNBI_ND_TLV_TYPE_IF_TYPE(9),
	SNBI_ND_TLV_TYPE_MAX(11);


    private Integer value;

    private SnbiNdTlvType(int value) {
        this.value = value;
    }

    /**
     * Get the value of the enum.
     * @return - The value of the enum.
     */
    public Integer getValue() {
        return this.value;
    }

    /**
     * Get the enum corresponding to a value.
     * @param value - The value of the enum.
     * @return - The enum corresponding to the value.
     */
    public static SnbiNdTlvType getEnumFromValue(short value) {
        for (SnbiNdTlvType type : SnbiNdTlvType.values()) {
            if (type.getValue() == value)
                return type;
        }
        return null;
    }
}

enum SnbiBsTlvType {
     SNBI_BS_TLV_TYPE_INVALID(0),
     SNBI_BS_TLV_TYPE_UDI(1),
     SNBI_BS_TLV_TYPE_DEVICE_ID(2),
     SNBI_BS_TLV_TYPE_DOMAIN_ID(3),
     SNBI_BS_TLV_TYPE_IF_V4ADDR(4),
     SNBI_BS_TLV_TYPE_IF_V6ADDR(5),
     SNBI_BS_TLV_TYPE_CERT_REQ(6),
     SNBI_BS_TLV_TYPE_CERT_REQ_SIGN(7),
     SNBI_BS_TLV_TYPE_CERT_RESP(8),
     SNBI_BS_TLV_TYPE_PUBLIC_KEY(9),
     SNBI_BS_TLV_TYPE_RA_V4ADDR(10),
     SNBI_BS_TLV_TYPE_RA_V6ADDR(11),
     SNBI_BS_TLV_TYPE_RA_SIGN(12),
     SNBI_BS_TLV_TYPE_SUDI_CERTIFICATE(13),
     SNBI_BS_TLV_TYPE_DOMAIN_CERTIFICATE(14),
     SNBI_BS_TLV_TYPE_RA_CERTIFICATE(15),
     SNBI_BS_TLV_TYPE_CA_CERTIFICATE(16),
     SNBI_BS_TLV_TYPE_RA_ID(17),
     SNBI_BS_TLV_TYPE_ACP_PAYLOAD(19),
     SNBI_BS_TLV_TYPE_DEST_UDI(20),
     SNBI_BS_TLV_TYPE_SERVICE(21),
     SNBI_BS_TLV_TYPE_MAX(24);

     private Integer value;

     private SnbiBsTlvType(int value) {
         this.value = value;
     }

     /**
      * Get the value of the enum.
      * @return - The value of the enum.
      */
     public Integer getValue() {
         return this.value;
     }

     /**
      * Get the enum corresponding to a value.
      * @param value - The value of the enum.
      * @return - The enum corresponding to the value.
      */
     public static SnbiBsTlvType getEnumFromValue(short value) {
         for (SnbiBsTlvType type : SnbiBsTlvType.values()) {
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
