package org.opendaylight.snbi.southplugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiNodeStateNewNbr extends SnbiNodeStateCommonEventHandlers implements ISnbiNodeState {
    private static final Logger log = LoggerFactory.getLogger(SnbiNodeStateNewNbr.class);

    SnbiNodeStateNewNbr (SnbiNode node) {
        super(node);
    }

    @Override
    public SnbiNodeState getState() {
        return SnbiNodeState.SNBI_NODE_STATE_NEW_NBR;
    }
    
    public SnbiNodeState nodeStateSetEvent () {
        log.debug("[node: "+node.getUDI()+"] Set state : "+this.getState());
        node.setProxyIPAddress(node.getRegistrar().getNodeself().getNodeAddress());
        node.startNewExpiryTimer();
        return node.getCurrState();
       // return (SnbiNodeState.SNBI_NODE_STATE_NI_CERT_REQUEST);
    }
}
