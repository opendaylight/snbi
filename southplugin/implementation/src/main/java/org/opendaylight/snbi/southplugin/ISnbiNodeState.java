package org.opendaylight.snbi.southplugin;

public interface ISnbiNodeState {
    public SnbiNodeState getState ();

    public SnbiNodeState handleNDRefreshPktEvent (SnbiPkt pkt);
    public SnbiNodeState handleNICertReqPktEvent (SnbiPkt pkt);
    public SnbiNodeState handleNICertRspPktEvent (SnbiPkt pkt);
    public SnbiNodeState handleNbrConnectPktEvent (SnbiPkt pkt);
    public SnbiNodeState handleBSReqPktEvent (SnbiPkt pkt);
    // The current node expired.
    public SnbiNodeState handleNodeExpiredEvent ();
    // Activate the current state.
    public SnbiNodeState nodeStateSetEvent ();
} 