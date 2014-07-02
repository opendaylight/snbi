package org.opendaylight.snbi.southplugin;

import java.util.LinkedList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A SNBI node discovered through SNBI.
 */
public class SnbiNode {
    // Node Expiry timer, if no keep alive is received for 40 seconds, the node
    // is deemed lost.
    private Timer nodeExpiryTimer = null;
    // The UDI of the node.
    private String nodeUdi = null;
    // The most recent Epoch time, when a refresh update was received.
    private long lastUpdateEpochTime;
    // Node expiry notification list.
    List<ISnbiNode> nodeExpiredNotifyList = null;
    // Logger.
    private static final Logger log = LoggerFactory.getLogger(SnbiNode.class);
    // The expiry time period.
    private static final Integer ndExpiryTime = 40 * 1000; // 40 seconds Expiry

    // timer.

    public SnbiNode(SnbiPkt pkt) {
        String udi = pkt.getTLVString(SnbiTLVType.SNBI_TLV_TYPE_UDI.getValue(),
                SnbiTLVSubtypeUDI.SNBI_TLV_STYPE_UDI.getValue());
        log.debug("New node created " + udi);
        this.nodeUdi = udi;
        nodeExpiredNotifyList = new LinkedList<ISnbiNode>();
        lastUpdateEpochTime = System.currentTimeMillis() / 1000L;
        startNewExpiryTimer();
    }

    /**
     * Start an Expiry Timer, if a timer already exists, then cancel/purge that
     * because we have received an update for this neighbor.
     */
    private void startNewExpiryTimer() {
        if (nodeExpiryTimer != null) {
            // We have received an update, so cancel the old timer.
            nodeExpiryTimer.cancel();
            nodeExpiryTimer.purge();
        }
        nodeExpiryTimer = new Timer("Neighbor Node Expiry Timer "
                + this.nodeUdi, true);
        nodeExpiryTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                handleExpiryTimer();
            }

        }, ndExpiryTime, ndExpiryTime);
    }

    /*
     * The node din't receive any updates for 40 seconds, declare this lost.
     */
    private void handleExpiryTimer() {
        for (ISnbiNode notifyNode : nodeExpiredNotifyList) {
            notifyNode.nodeExpiredNotification(this);
        }
    }

    /**
     * Get the UDI of the node.
     *
     * @return - The UDI string of the node.
     */
    public String getUDI() {
        return this.nodeUdi;
    }

    /**
     * Received a new hello packet, restart the Expiry timer.
     *
     * @param pkt
     */
    public void handleHelloRefreshPacket(SnbiPkt pkt) {
        if (pkt.getTLVString(SnbiTLVType.SNBI_TLV_TYPE_UDI.getValue(),
                SnbiTLVSubtypeUDI.SNBI_TLV_STYPE_UDI.getValue()) == this.nodeUdi) {
            return;
        }
        lastUpdateEpochTime = System.currentTimeMillis() / 1000L;
        startNewExpiryTimer();
    }

    /**
     * Register for node expiry events.
     *
     * @param notifyNode
     */
    public void registerNodeExpiryNotification(ISnbiNode notifyNode) {
        if (nodeExpiredNotifyList == null) {
            nodeExpiredNotifyList = new LinkedList<ISnbiNode>();
        }
        nodeExpiredNotifyList.add(notifyNode);
    }

    protected void finalize() {
        if (nodeExpiryTimer != null) {
            nodeExpiryTimer.cancel();
            nodeExpiryTimer.purge();
        }

        if (nodeExpiredNotifyList != null) {
            nodeExpiredNotifyList.clear();
        }
    }
}

/**
 * Interface for the SnbiNode services.
 */
interface ISnbiNode {
    /**
     * Notify SnbiNode expired event.
     *
     * @param node
     *            - The node that got expired.
     */
    public void nodeExpiredNotification(SnbiNode node);
}
