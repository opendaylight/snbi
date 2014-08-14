package org.opendaylight.snbi.southplugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiNodeStateBootStrap extends SnbiNodeStateCommonEventHandlers implements ISnbiNodeState {
 
    private static Logger log = LoggerFactory.getLogger(SnbiNodeStateBootStrap.class);
    
    public SnbiNodeStateBootStrap(SnbiNode node) {
        super(node);
    }

    @Override
    public SnbiNodeState getState() {
        return SnbiNodeState.SNBI_NODE_STATE_BOOTSTRAP;
    }

    @Override
    public SnbiNodeState nodeStateSetEvent() {
        SnbiPkt pkt = new SnbiPkt(SnbiProtocolType.SNBI_PROTOCOL_BOOTSTRAP,
                                  SnbiMsgType.SNBI_MSG_BS_RESP);
        
        pkt.setDstIP(node.getProxyIPAddress());
        pkt.setSrcIP(node.getRegistrar().getNodeself().getNodeAddress());
        
        
        return node.getCurrState();
    }

}
