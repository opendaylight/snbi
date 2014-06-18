package org.opendaylight.controller.snbi.internal;

import java.util.List;

import org.eclipse.osgi.framework.console.CommandInterpreter;
import org.eclipse.osgi.framework.console.CommandProvider;
import org.opendaylight.controller.snbi.Snbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;

/**
 * The internal SNBI services.
 */
public class SnbiInternal implements CommandProvider {

    private static final Logger log = LoggerFactory
            .getLogger(SnbiInternal.class);
    private static final String dbgString = "SNBI:Internal:";
    Snbi snbiInstance = null;

    public String getHelp() {
        StringBuffer help = new StringBuffer();
        help.append("---SNBI Service Testing---\n");
        help.append("\tSnbiStart         - Provide a Domain Name");
        return help.toString();
    }

    public void _SnbiStart(CommandInterpreter ci) {
        String domainName = ci.nextArgument();
        if (domainName == null) {
            ci.println("Domain Name not provided.");
            return;
        }
        snbiInstance = new Snbi(domainName);
        log.info("Starting Snbi Service for domain " + domainName);
        snbiInstance.snbiStart();
    }

    public void _SnbiStop(CommandInterpreter ci) {
        String domainName = ci.nextArgument();
        if (domainName == null) {
            ci.println("Domain Name not provided.");
            return;
        }
        snbiInstance.snbiStop();
    }

    public void _SnbiShowNeighbors(CommandInterpreter ci) {
        String domainName = ci.nextArgument();
        List<SnbiNode> nodes = null;
        if (domainName == null) {
            ci.println("Domain Name not provided.");
            return;
        }
        nodes = snbiInstance.getNeighbors();
        for (SnbiNode node : nodes) {
            System.out.println(" UDI: " + node.getUDI());
        }
    }

    private void registerWithOSGIConsole() {
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass())
                .getBundleContext();
        bundleContext.registerService(CommandProvider.class.getName(), this,
                null);
    }

    public SnbiInternal() throws Exception {
        log.debug("Snbi Constructort");
    }

    void init() {
        log.debug("INIT called!");
    }

    void destroy() {
        log.debug("DESTROY called!");
    }

    void start() throws Exception {
        log.debug("START called!");
        try {
            // Get instance will also init Messaging Infra.
            SnbiMessagingInfra.getInstance();
        } catch (Exception excpt) {
            throw excpt;
        }
        registerWithOSGIConsole();
    }

    void stop() {
        log.debug("STOP called!");
    }
}

/**
 * The Message types supported.
 */
enum SnbiMsgType {
    SNBI_MSG_ND_HELLO(1), SNBI_MSG_ND_BYE(2);
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
    SNBI_TLV_TYPE_UDI((short) 1), SNBI_TLV_TYPE_IPADDR((short) 6), SNBI_TLV_TYPE_IFNAME(
            (short) 7);

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
    SNBI_PROTOCOL_CHANNEL_DISCOVERY((short) 1), SNBI_PROTOCOL_ADJACENCY_DISCOVERY(
            (short) 2), SNBI_PROTOCOL_ACP((short) 3), SNBI_PROTOCOL_CNP(
            (short) 4);
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