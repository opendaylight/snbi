/*
 * Copyright (c) 2014, 2015 Cisco Systems, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.snbi.southplugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnbiNodeStateBootStrapIgnore extends SnbiNodeStateCommonEventHandlers implements ISnbiNodeState {
    private static final Logger log = LoggerFactory.getLogger(SnbiNodeStateBootStrapIgnore.class);

	public SnbiNodeStateBootStrapIgnore(SnbiNode node) {
		super(node);
	}

    @Override
    public SnbiNodeState getState() {
        return SnbiNodeState.SNBI_NODE_STATE_BOOTSTRAP_IGNORE;
    }

	@Override
	public SnbiNodeState nodeStateSetEvent(eventContext evnt) {
		return node.getCurrState();
	}
	@Override
	public SnbiNodeState handleNodeBSReqPktEvent (SnbiPkt pkt) {
        log.debug("[node:"+node.getUDI()+"] Handle BSReq Pkt Event Ignored: "+pkt.getUDITLV());
        return node.getCurrState();
	}
}
