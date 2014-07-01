package org.opendaylight.snbi.southplugin;

import java.net.NetworkInterface;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

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
    // TLV hash list.
    private Map<Short, LinkedList<TLV>> TLVHashList = null;
    /*
     * Header length is a combination of the following. protocol version (4bits)
     * + reserved bits (4bits) + protocol type (8bits) + flags (8bits) +
     * hoplimit (8bits) + message type (16bits) + msglength (16bits).
     */
    private static final byte SNBIHEADERLENGTH = 8;
    /*
     * The interface on which the packet was received on.
     */
    private NetworkInterface intf = null;

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
        this.protocolVersion = 1;
        this.reservedBits = 0;
        this.protocolType = protocolType;
        this.msgType = msgType;
        this.hopLimit = 255;
        // 1 byte reservedBits + ProtocolVersion, 1 byte protocolType, 1 byte
        // flags, 1 byte hoplimit, 2 bytes msgType, 2 byte msglength.
        this.msgLength = (int) SNBIHEADERLENGTH;
        this.flags = 0;
        this.TLVHashList = new HashMap<Short, LinkedList<TLV>>();
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

        try {
            this.TLVHashList = new HashMap<Short, LinkedList<TLV>>();
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

    /**
     * The network interface on which the packet should be sent out on.
     *
     * @param intf
     *            - The interface on which the packet should be sent out on or
     *            received from.
     */
    public void setInterface(NetworkInterface intf) {
        this.intf = intf;
    }

    /**
     * Get the network interface.
     *
     * @return - The network interface that is set on the packet.
     */
    public NetworkInterface getInterface() {
        return (this.intf);
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
    }

    /*
     * Parse the TLVs.
     */
    private void parseMsgTLVs(ByteBuffer msgByteStream) {
        TLV tlv = null;
        short tlvType;
        short tlvStype;
        int length;
        byte[] value = null;
        // For now we assume that we have parsed over the headers. Parse the
        // TLVs now.
        while (msgByteStream.hasRemaining()) {
            tlvType = msgByteStream.get();
            tlvStype = msgByteStream.get();
            length = msgByteStream.getShort() - TLV.SNBITLVHEADERLENGTH;
            value = new byte[length];
            msgByteStream.get(value);
            tlv = new TLV(tlvType, tlvStype, value, length);
            // Only add the TLV, no need to increment the message length.
            addTLVInternal(tlv);
        }
    }

    /**
     * Get the first string value in the TLV list corresponding to a type and
     * subtype.
     *
     * @param type
     *            - The type of the TLV.
     * @param stype
     *            - The subtype of the TLV.
     * @return - The TLV string corresponding to a type and subtype.
     */
    public String getTLVString(short type, short stype) {
        List<TLV> tlvlist = getTLV(type);
        if (tlvlist == null) {
            return null;
        }
        for (TLV tlv : tlvlist) {
            if (tlv.getSubType() == stype) {
                return new String(tlv.getValue());
            }
        }
        return null;
    }

    /**
     * Get the TLV list of a particular type.
     *
     * @param type
     *            - The type of the TLV.
     * @return the TLV list for a particular type.
     */
    public List<TLV> getTLV(short type) {
        if (TLVHashList == null) {
            return null;
        }
        return TLVHashList.get(type);
    }

    /**
     * Get the TLV list for a particular type and subtype.
     *
     * @param type
     *            - the type of the TLV.
     * @param stype
     *            - The sub type of the TLV.
     * @return The TLV list for a particular type and subtype.
     */
    public List<TLV> getTLV(short type, short stype) {
        List<TLV> tlvlist = new LinkedList<TLV>();
        if (TLVHashList == null) {
            return null;
        }

        for (TLV tlv : TLVHashList.get(type)) {
            if (tlv.getSubType() == stype) {
                tlvlist.add(tlv);
            }
        }
        return tlvlist;
    }

    /**
     * Add a TLV to the message.
     *
     * @param tlv
     *            - The TLV to be added.
     */
    public void addTLV(TLV tlv) {
        // Update the message length.
        this.msgLength += (TLV.SNBITLVHEADERLENGTH + tlv.getLength());
        addTLVInternal(tlv);
    }

    private void addTLVInternal(TLV tlv) {
        if (TLVHashList == null) {
            this.TLVHashList = new HashMap<Short, LinkedList<TLV>>();
        }
        LinkedList<TLV> tlvTypeList = TLVHashList.get(tlv.getType());
        if (tlvTypeList == null) {
            tlvTypeList = new LinkedList<TLV>();
            TLVHashList.put(tlv.getType(), tlvTypeList);
        }
        tlvTypeList.add(tlv);
        log.debug("New TLV added type " + tlv.getType() + " subType "
                + tlv.getSubType() + "Length " + tlv.getLength());
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
        updateMsgHeader(msgByteStream);
        updateMsgTLVs(msgByteStream);
        return msgByteStream.array();
    }

    private void updateMsgHeader(ByteBuffer msgByteStream) {
        if (msgByteStream == null) {
            return;
        }
        msgByteStream.put((byte) (reservedBits | protocolVersion << 4));
        msgByteStream.put(protocolType.getValue().byteValue());
        msgByteStream.put(flags.byteValue());
        msgByteStream.put(hopLimit.byteValue());
        msgByteStream.putShort(msgType.getValue().shortValue());
        msgByteStream.putShort(msgLength.shortValue());
    }

    private void updateMsgTLVs(ByteBuffer msgByteStream) {
        short tlvlength = 0;
        if (msgByteStream == null) {
            return;
        }
        for (Map.Entry<Short, LinkedList<TLV>> TLVlistEntry : TLVHashList
                .entrySet()) {
            LinkedList<TLV> TLVlist = TLVlistEntry.getValue();
            for (TLV tlv : TLVlist) {
                msgByteStream.put(tlv.getType().byteValue());
                msgByteStream.put(tlv.getSubType().byteValue());
                tlvlength = (short) (TLV.SNBITLVHEADERLENGTH + tlv.getLength()
                        .shortValue());
                msgByteStream.putShort(tlvlength);
                msgByteStream.put(tlv.getValue());
            }
        }
    }
}

/**
 * SNBI TLV class This is different from the normal type in that it contains a
 * type and a subtype.
 */
class TLV {
    private Short type; // 8 bits + 1 byte = 16 bits.
    private Short subType; // 8 bits + 1 byte = 16 bits.
    private Integer length; // 16 bits + 2 byte = 32 bits
    private byte[] value;
    /*
     * TLV header length Type (8 bits) + subtype (8bits) Length (16bits).
     */
    public static final byte SNBITLVHEADERLENGTH = 4;

    /**
     * create TLV with the given type, subtype, value and length.
     *
     * @param type
     * @param subType
     * @param value
     * @param length
     */
    public TLV(Short type, Short subType, byte[] value, Integer length) {
        this.subType = subType;
        this.type = type;
        this.length = length;
        this.value = value;
    }

    /**
     * Get the type of the TLV.
     */
    public Short getType() {
        return type;
    }

    /**
     * Get the subtype of the TLV.
     *
     * @return - The subtype of the TLV.
     */
    public Short getSubType() {
        return subType;
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
