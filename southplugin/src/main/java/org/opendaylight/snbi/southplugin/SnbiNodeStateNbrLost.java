package org.opendaylight.snbi.southplugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiNodeStateNbrLost extends SnbiNodeStateCommonEventHandlers implements ISnbiNodeState {
    private static final Logger log = LoggerFactory.getLogger(SnbiNodeStateNewNbr.class);

    public SnbiNodeStateNbrLost (SnbiNode node) {
        super(node);
    }
    
    public SnbiNodeState getState () {
        return SnbiNodeState.SNBI_NODE_STATE_NBR_LOST;
    }

    @Override
    public SnbiNodeState nodeStateSetEvent(eventContext evt) {
        log.debug("[node:"+node.getUDI()+"] Set state : "+this.getState());
        return node.getCurrState();
    }

}
